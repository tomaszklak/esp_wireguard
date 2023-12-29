
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/random.h>
#include <sys/socket.h>
#include "sodium.h"
#include "esp_log.h"
#include "esp_transport.h"
#include "esp_transport_tcp.h"
#include "esp_transport_derp.h"
#include "esp_transport_internal.h"
#include "errno.h"
#include "esp_tls_crypto.h"

static const char *TAG = "TRANSPORT_DERP";

#define DERP_BUFFER_SIZE              CONFIG_DERP_BUFFER_SIZE

#define DERP_FRAME_TYPE_NONE            0x00
#define DERP_FRAME_TYPE_SERVER_KEY      0x01
#define DERP_FRAME_TYPE_CLIENT_INFO     0x02
#define DERP_FRAME_TYPE_SERVER_INFO     0x03
#define DERP_FRAME_TYPE_SEND_PACKET     0x04
#define DERP_FRAME_TYPE_RECV_PACKET     0x05
#define DERP_FRAME_TYPE_KEEP_ALIVE      0x06
#define DERP_FRAME_TYPE_NOTE_PREFFERED  0x07
#define DERP_FRAME_TYPE_PEER_GONE       0x08
#define DERP_FRAME_TYPE_PEER_PERSISTENT 0x09
#define DERP_FRAME_TYPE_WATCH_CONNS     0x10
#define DERP_FRAME_TYPE_CLOSE_PEER      0x11
#define DERP_FRAME_TYPE_PING            0x12
#define DERP_FRAME_TYPE_PONG            0x13
#define DERP_FRAME_TYPE_CONTROL_MESSAGE 0x14

#define DERP_SIZE16                   126
#define DERP_SIZE64                   127
#define MAX_DERP_HEADER_SIZE          16
#define DERP_RESPONSE_OK              101
#define DERP_TRANSPORT_MAX_CONTROL_FRAME_BUFFER_LEN 125


typedef struct {
    uint8_t frame_type;
    int payload_len;                    /*!< Total length of the payload */
    int bytes_remaining;                /*!< Bytes left to read of the payload  */
    bool header_received;               /*!< Flag to indicate that a new message header was received */
} derp_transport_frame_state_t;

typedef struct {
    char *buffer;
    char *user_agent;
    char *headers;
    // Node's secret key
    const char* secret_key;
    // Nodes public key
    const char* public_key;
    derp_transport_frame_state_t frame_state;
    esp_transport_handle_t parent;
} transport_derp_t;

/**
 * @brief               Handles control frames
 *
 * This API is used internally to handle control frames at the transport layer.
 * The API could be possibly promoted to a public API if needed by some clients
 *
 * @param t             Derp transport handle
 * @param buffer        Buffer with the actual payload of the control packet to be processed
 * @param len           Length of the buffer (typically the same as the payload buffer)
 * @param timeout_ms    The timeout milliseconds
 * @param client_closed To indicate that the connection has been closed by the client
*                       (to prevent echoing the CLOSE packet if true, as this is the actual echo from the server)
 *
 * @return
 *      0 - no activity, or successfully responded to PING
 *      -1 - Failure: Error on read or the actual payload longer then buffer
 *      1 - Close handshake success
 *      2 - Got PONG message
 */

static int esp_transport_derp_handle_control_frames(esp_transport_handle_t t, char *buffer, int len, int timeout_ms, bool client_closed);

static inline uint8_t derp_get_bin_frame_type(derp_transport_frame_type_t frame_type)
{
    return (uint8_t)frame_type;
}

static esp_transport_handle_t derp_get_payload_transport_handle(esp_transport_handle_t t)
{
    transport_derp_t *derp = esp_transport_get_context_data(t);

    /* Reading parts of a frame directly will disrupt the derp internal frame state,
        reset bytes_remaining to prepare for reading a new frame */
    derp->frame_state.bytes_remaining = 0;

    return derp->parent;
}

static char *trimwhitespace(const char *str)
{
    char *end;

    // Trim leading space
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) {
        return (char *)str;
    }

    // Trim trailing space
    end = (char *)(str + strlen(str) - 1);
    while (end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator
    *(end + 1) = 0;

    return (char *)str;
}

static char *get_http_header(const char *buffer, const char *key)
{
    char *found = strcasestr(buffer, key);
    if (found) {
        found += strlen(key);
        char *found_end = strstr(found, "\r\n");
        if (found_end) {
            found_end[0] = 0;//terminal string

            return trimwhitespace(found);
        }
    }
    return NULL;
}

static int derp_connect(esp_transport_handle_t t, const char *host, int port, int timeout_ms)
{
    transport_derp_t *derp = esp_transport_get_context_data(t);
    if (esp_transport_connect(derp->parent, host, port, timeout_ms) < 0) {
        ESP_LOGE(TAG, "Error connecting to host %s:%d", host, port);
        return -1;
    }

    // Size of base64 coded string is equal '((input_size * 4) / 3) + (input_size / 96) + 6' including Z-term
    unsigned char client_key[28] = {0};

    /// 8 bytes of magic message prefix: `DERP🔑`
    const uint8_t MAGIC[8] = [0x44, 0x45, 0x52, 0x50, 0xF0, 0x9F, 0x94, 0x91];

    const char *user_agent_ptr = (derp->user_agent)?(derp->user_agent):"ESP32 Derp Client";

    size_t outlen = 0;
    int len = snprintf(derp->buffer, DERP_BUFFER_SIZE,
                         "GET %s HTTP/1.1\r\n"
                         "Connection: Upgrade\r\n"
                         "Host: %s:%d\r\n"
                         "User-Agent: %s\r\n"
                         "Upgrade: WebSocket\r\n"
                        //  "Keep-Alive: tcp=15, derp=60\r\n"
                         "/derp",
                         host, port, user_agent_ptr);
    if (len <= 0 || len >= DERP_BUFFER_SIZE) {
        ESP_LOGE(TAG, "Error in request generation, desired request len: %d, buffer size: %d", len, DERP_BUFFER_SIZE);
        return -1;
    }
    if (derp->headers) {
        ESP_LOGD(TAG, "headers: %s", derp->headers);
        int r = snprintf(derp->buffer + len, DERP_BUFFER_SIZE - len, "%s", derp->headers);
        len += r;
        if (r <= 0 || len >= DERP_BUFFER_SIZE) {
            ESP_LOGE(TAG, "Error in request generation"
                          "(strncpy of headers returned %d, desired request len: %d, buffer size: %d", r, len, DERP_BUFFER_SIZE);
            return -1;
        }
    }
    int r = snprintf(derp->buffer + len, DERP_BUFFER_SIZE - len, "\r\n");
    len += r;
    if (r <= 0 || len >= DERP_BUFFER_SIZE) {
        ESP_LOGE(TAG, "Error in request generation"
                       "(snprintf of header terminal returned %d, desired request len: %d, buffer size: %d", r, len, DERP_BUFFER_SIZE);
        return -1;
    }
    ESP_LOGD(TAG, "Write upgrade request\r\n%s", derp->buffer);
    if (esp_transport_write(derp->parent, derp->buffer, len, timeout_ms) <= 0) {
        ESP_LOGE(TAG, "Error write Upgrade header %s", derp->buffer);
        return -1;
    }
    int rsp_len = 0;
    do {
        if ((len = esp_transport_read(derp->parent, derp->buffer + rsp_len, DERP_BUFFER_SIZE - rsp_len, timeout_ms)) <= 0) {
            ESP_LOGE(TAG, "Error read response for Upgrade header %s", derp->buffer);
            return -1;
        }
        rsp_len += len;
        derp->buffer[rsp_len] = '\0';
        ESP_LOGD(TAG, "Read header chunk %d, current header size: %d", len, rsp_len);
    } while (NULL == strstr(derp->buffer, "\r\n\r\n") && rsp_len < DERP_BUFFER_SIZE);

    char *upgrade = get_http_header(derp->buffer, "Upgrade:");
    if (upgrade == NULL) {
        ESP_LOGE(TAG, "\"Upgrade\" header not found");
        return -1;
    }

    // TODO check if upgrade == "DERP"

    char *server_pk = get_http_header(derp->buffer, "Derp-Public-Key:");
    if (server_pk == NULL) {
        ESP_LOGE(TAG, "\"Derp-Public-Key\" header not found");
        return -1;
    }

    // TODO check if base64(server_pk) == base64(derp->config->server.public_key)

    char *data_start = strstr(derp->buffer, "\r\n\r\n");
    if (data_start == NULL) {
        ESP_LOGE(TAG, "Error parsing response");
        return -1;
    }
    // Skip "\r\n\r\n"
    data_start += 4;
    size_t data_len = &derp->buffer[rsp_len] - data_start;

    if (data_len != 45) {
        ESP_LOGE(TAG, "Response length is not 45 bytes");
        return -1;
    }

    if (data_start != DERP_FRAME_TYPE_SERVER_KEY) {
        ESP_LOGE(TAG, "Error parsing response");
        return -1;
    }

    char* magic_start = data_start + 1;

    if (memcmp(magic_start, MAGIC, sizeof(MAGIC)) != 0) {
        ESP_LOGE(TAG, "Error parsing response");
        return -1;
    }

    char* server_pubkey_start = magic_start + sizeof(MAGIC);

    const char* plain_text = "{\"version\": 2, \"meshKey\": \"\"}";
    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char ciphertext[crypto_box_MACBYTES + sizeof(plain_text)];
    randombytes_buf(nonce, sizeof nonce);

    if (crypto_box_easy(ciphertext, plain_text, sizeof(plain_text), nonce, server_pubkey_start, derp->secret_key) != 0) {
        ESP_LOGE(TAG, "Error encrypting client key");
        return -1;
    }

    int outbuf_len = 0;

    memcpy(client->buffer, DERP_FRAME_TYPE_CLIENT_INFO, 1);
    outbuf_len += 1;
    if (outbuf_len <= 0 || len >= DERP_BUFFER_SIZE) {
        ESP_LOGE(TAG, "Error in request generation, desired request len: %d, buffer size: %d", len, DERP_BUFFER_SIZE);
        return -1;
    }

    memcpy(client->buffer + outbuf_len, client->public_key, PUBKEY_LEN);
    outbuf_len += PUBKEY_LEN;
    if (outbuf_len <= 0 || len >= DERP_BUFFER_SIZE) {
        ESP_LOGE(TAG, "Error in request generation, desired request len: %d, buffer size: %d", len, DERP_BUFFER_SIZE);
        return -1;
    }

    memcpy(client->buffer + outbuf_len, nonce, crypto_box_NONCEBYTES);
    outbuf_len += crypto_box_NONCEBYTES;
    if (outbuf_len <= 0 || len >= DERP_BUFFER_SIZE) {
        ESP_LOGE(TAG, "Error in request generation, desired request len: %d, buffer size: %d", len, DERP_BUFFER_SIZE);
        return -1;
    }

    memcpy(client->buffer + outbuf_len, ciphertext, sizeof(ciphertext));
    outbuf_len += sizeof(ciphertext);
    if (outbuf_len <= 0 || len >= DERP_BUFFER_SIZE) {
        ESP_LOGE(TAG, "Error in request generation, desired request len: %d, buffer size: %d", len, DERP_BUFFER_SIZE);
        return -1;
    }

    ESP_LOGD(TAG, "Write upgrade request\r\n%s", derp->buffer);
    if (esp_transport_write(derp->parent, derp->buffer, outbuf_len, timeout_ms) <= 0) {
        ESP_LOGE(TAG, "Error write Upgrade header %s", derp->buffer);
        return -1;
    }

    int rsp_len = 0;
    if ((len = esp_transport_read(derp->parent, derp->buffer + rsp_len, DERP_BUFFER_SIZE - rsp_len, timeout_ms)) <= 0) {
        ESP_LOGE(TAG, "Error read response for ServerInfo header %s", derp->buffer);
        return -1;
    }
    rsp_len += len;
    derp->buffer[rsp_len] = '\0';
    ESP_LOGD(TAG, "Read header chunk %d, current header size: %d", len, rsp_len);

    if (derp->buffer[0] != DERP_FRAME_TYPE_SERVER_INFO) {
        ESP_LOGE(TAG, "Error parsing ServerInfo response");
        return -1;
    }

    return 0;
}

static int _derp_write(esp_transport_handle_t t, int frame_type, const char *b, int len, int timeout_ms)
{
    transport_derp_t *derp = esp_transport_get_context_data(t);
    char derp_header;
    int header_len = 0, i;

    int poll_write;
    if ((poll_write = esp_transport_poll_write(derp->parent, timeout_ms)) <= 0) {
        ESP_LOGE(TAG, "Error transport_poll_write");
        return poll_write;
    }

    derp_header = frame_type;

    if (esp_transport_write(derp->parent, &derp_header, 1, timeout_ms) != header_len) {
        ESP_LOGE(TAG, "Error write header");
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    int ret = esp_transport_write(derp->parent, b, len, timeout_ms);

    return ret;
}

int esp_transport_derp_send_raw(esp_transport_handle_t t, derp_transport_frame_type_t frame_type, const char *b, int len, int timeout_ms)
{
    uint8_t frame_type = derp_get_bin_frame_type(frame_type);
    if (t == NULL) {
        ESP_LOGE(TAG, "Transport must be a valid derp handle");
        return ESP_ERR_INVALID_ARG;
    }
    ESP_LOGD(TAG, "Sending raw derp message with frame_type %d", frame_type);
    return _derp_write(t, (int)frame_type, b, len, timeout_ms);
}

static int derp_write(esp_transport_handle_t t, const char *b, int len, int timeout_ms)
{
    return _derp_write(t, DERP_FRAME_TYPE_SEND_PACKET, b, len, timeout_ms);
}

static int derp_read_payload(esp_transport_handle_t t, char *buffer, int len, int timeout_ms)
{
    transport_derp_t *derp = esp_transport_get_context_data(t);

    int bytes_to_read;
    int rlen = 0;

    if (derp->frame_state.bytes_remaining > len) {
        ESP_LOGD(TAG, "Actual data to receive (%d) are longer than derp buffer (%d)", derp->frame_state.bytes_remaining, len);
        bytes_to_read = len;
    } else {
        bytes_to_read = derp->frame_state.bytes_remaining;
    }

    // Receive and process payload
    if (bytes_to_read != 0 && (rlen = esp_transport_read(derp->parent, buffer, bytes_to_read, timeout_ms)) <= 0) {
        ESP_LOGE(TAG, "Error read data");
        return rlen;
    }
    derp->frame_state.bytes_remaining -= rlen;

    return rlen;
}


/* Read and parse the derp header, determine length of payload */
static int derp_read_header(esp_transport_handle_t t, char *buffer, int len, int timeout_ms)
{
    transport_derp_t *derp = esp_transport_get_context_data(t);
    int payload_len;

    char derp_header[MAX_DERP_HEADER_SIZE];
    char *data_ptr = derp_header, mask;
    int rlen;
    int poll_read;
    derp->frame_state.header_received = false;
    if ((poll_read = esp_transport_poll_read(derp->parent, timeout_ms)) <= 0) {
        return poll_read;
    }

    // Receive and process header first (based on header size)
    int header = 2;
    int mask_len = 4;
    if ((rlen = esp_transport_read(derp->parent, data_ptr, header, timeout_ms)) <= 0) {
        ESP_LOGE(TAG, "Error read data");
        return rlen;
    }
    derp->frame_state.header_received = true;
    derp->frame_state.frame_type = (*data_ptr & 0x0F);
    data_ptr ++;
    mask = ((*data_ptr >> 7) & 0x01);
    payload_len = (*data_ptr & 0x7F);
    data_ptr++;
    ESP_LOGD(TAG, "frame_type: %d, mask: %d, len: %d\r\n", derp->frame_state.frame_type, mask, payload_len);
    if (payload_len == 126) {
        // headerLen += 2;
        if ((rlen = esp_transport_read(derp->parent, data_ptr, header, timeout_ms)) <= 0) {
            ESP_LOGE(TAG, "Error read data");
            return rlen;
        }
        payload_len = data_ptr[0] << 8 | data_ptr[1];
    } else if (payload_len == 127) {
        // headerLen += 8;
        header = 8;
        if ((rlen = esp_transport_read(derp->parent, data_ptr, header, timeout_ms)) <= 0) {
            ESP_LOGE(TAG, "Error read data");
            return rlen;
        }

        if (data_ptr[0] != 0 || data_ptr[1] != 0 || data_ptr[2] != 0 || data_ptr[3] != 0) {
            // really too big!
            payload_len = 0xFFFFFFFF;
        } else {
            payload_len = data_ptr[4] << 24 | data_ptr[5] << 16 | data_ptr[6] << 8 | data_ptr[7];
        }
    }

    if (mask) {
        // Read and store mask
        if (payload_len != 0 && (rlen = esp_transport_read(derp->parent, buffer, mask_len, timeout_ms)) <= 0) {
            ESP_LOGE(TAG, "Error read data");
            return rlen;
        }
        memcpy(derp->frame_state.mask_key, buffer, mask_len);
    } else {
        memset(derp->frame_state.mask_key, 0, mask_len);
    }

    derp->frame_state.payload_len = payload_len;
    derp->frame_state.bytes_remaining = payload_len;

    return payload_len;
}

static int derp_read(esp_transport_handle_t t, char *buffer, int len, int timeout_ms)
{
    int rlen = 0;
    transport_derp_t *derp = esp_transport_get_context_data(t);

    // If message exceeds buffer len then subsequent reads will skip reading header and read whatever is left of the payload
    if (derp->frame_state.bytes_remaining <= 0) {

        if ( (rlen = derp_read_header(t, buffer, len, timeout_ms)) < 0) {
            // If something when wrong then we prepare for reading a new header
            derp->frame_state.bytes_remaining = 0;
            return rlen;
        }

        if (rlen == 0) {
            derp->frame_state.bytes_remaining = 0;
            return 0; // timeout
        }
    }

    if (derp->frame_state.payload_len) {
        if ( (rlen = derp_read_payload(t, buffer, len, timeout_ms)) <= 0) {
            ESP_LOGE(TAG, "Error reading payload data");
            derp->frame_state.bytes_remaining = 0;
            return rlen;
        }
    }

    return rlen;
}


static int derp_poll_read(esp_transport_handle_t t, int timeout_ms)
{
    transport_derp_t *derp = esp_transport_get_context_data(t);
    return esp_transport_poll_read(derp->parent, timeout_ms);
}

static int derp_poll_write(esp_transport_handle_t t, int timeout_ms)
{
    transport_derp_t *derp = esp_transport_get_context_data(t);
    return esp_transport_poll_write(derp->parent, timeout_ms);;
}

static int derp_close(esp_transport_handle_t t)
{
    transport_derp_t *derp = esp_transport_get_context_data(t);
    return esp_transport_close(derp->parent);
}

static esp_err_t derp_destroy(esp_transport_handle_t t)
{
    transport_derp_t *derp = esp_transport_get_context_data(t);
    free(derp->buffer);
    free(derp->user_agent);
    free(derp->headers);
    free(derp);
    return 0;
}

static int derp_get_socket(esp_transport_handle_t t)
{
    if (t) {
        transport_derp_t *derp = t->data;
        if (derp && derp->parent && derp->parent->_get_socket) {
            return derp->parent->_get_socket(derp->parent);
        }
    }
    return -1;
}

esp_transport_handle_t esp_transport_derp_init(esp_transport_handle_t parent_handle)
{
    if (parent_handle == NULL || parent_handle->foundation == NULL) {
      ESP_LOGE(TAG, "Invalid parent ptotocol");
      return NULL;
    }
    esp_transport_handle_t t = esp_transport_init();
    if (t == NULL) {
        return NULL;
    }
    transport_derp_t *derp = calloc(1, sizeof(transport_derp_t));
    ESP_TRANSPORT_MEM_CHECK(TAG, derp, return NULL);
    derp->parent = parent_handle;
    t->foundation = parent_handle->foundation;

    derp->buffer = malloc(DERP_BUFFER_SIZE);
    ESP_TRANSPORT_MEM_CHECK(TAG, derp->buffer, {
        free(derp);
        esp_transport_destroy(t);
        return NULL;
    });

    esp_transport_set_func(t, derp_connect, derp_read, derp_write, derp_close, derp_poll_read, derp_poll_write, derp_destroy);
    // derp underlying transfer is the payload transfer handle
    esp_transport_set_parent_transport_func(t, derp_get_payload_transport_handle);

    esp_transport_set_context_data(t, derp);
    t->_get_socket = derp_get_socket;
    return t;
}

esp_err_t esp_transport_derp_set_user_agent(esp_transport_handle_t t, const char *user_agent)
{
    if (t == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    transport_derp_t *derp = esp_transport_get_context_data(t);
    if (derp->user_agent) {
        free(derp->user_agent);
    }
    if (user_agent == NULL) {
        derp->user_agent = NULL;
        return ESP_OK;
    }
    derp->user_agent = strdup(user_agent);
    if (derp->user_agent == NULL) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t esp_transport_derp_set_headers(esp_transport_handle_t t, const char *headers)
{
    if (t == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    transport_derp_t *derp = esp_transport_get_context_data(t);
    if (derp->headers) {
        free(derp->headers);
    }
    if (headers == NULL) {
        derp->headers = NULL;
        return ESP_OK;
    }
    derp->headers = strdup(headers);
    if (derp->headers == NULL) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t esp_transport_derp_set_config(esp_transport_handle_t t, const esp_transport_derp_config_t *config)
{
    if (t == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = ESP_OK;
    transport_derp_t *derp = esp_transport_get_context_data(t);
    if (config->user_agent) {
        err = esp_transport_derp_set_user_agent(t, config->user_agent);
        ESP_TRANSPORT_ERR_OK_CHECK(TAG, err, return err;)
    }
    if (config->headers) {
        err = esp_transport_derp_set_headers(t, config->headers);
        ESP_TRANSPORT_ERR_OK_CHECK(TAG, err, return err;)
    }

    return err;
}

derp_transport_frame_type_t esp_transport_derp_get_read_frame_type(esp_transport_handle_t t)
{
    transport_derp_t *derp = esp_transport_get_context_data(t);
    if (derp->frame_state.header_received) {
        // convert the header byte to enum if correctly received
        return (derp_transport_frame_type_t)derp->frame_state.frame_type;
    }
    return derp_frame_type_None;
}

int esp_transport_derp_get_read_payload_len(esp_transport_handle_t t)
{
    transport_derp_t *derp = esp_transport_get_context_data(t);
    return derp->frame_state.payload_len;
}

static int esp_transport_derp_handle_control_frames(esp_transport_handle_t t, char *buffer, int len, int timeout_ms, bool client_closed)
{
    transport_derp_t *derp = esp_transport_get_context_data(t);

    // If no new header reception in progress, or not a control frame
    // just pass 0 -> no need to handle control frames
    if (derp->frame_state.header_received == false ||
        !(derp->frame_state.frame_type & DERP_OPCODE_CONTROL_FRAME)) {
        return 0;
    }
    int actual_len;
    int payload_len = derp->frame_state.payload_len;

    ESP_LOGD(TAG, "Handling control frame with %d bytes payload", payload_len);
    if (payload_len > len) {
        ESP_LOGE(TAG, "Not enough room for processing the payload (need=%d, available=%d)", payload_len, len);
        derp->frame_state.bytes_remaining = payload_len - len;
        return -1;
    }

    return 0;
}

int esp_transport_derp_poll_connection_closed(esp_transport_handle_t t, int timeout_ms)
{
    struct timeval timeout;
    int sock = esp_transport_get_socket(t);
    fd_set readset;
    fd_set errset;
    FD_ZERO(&readset);
    FD_ZERO(&errset);
    FD_SET(sock, &readset);
    FD_SET(sock, &errset);

    int ret = select(sock + 1, &readset, NULL, &errset, esp_transport_utils_ms_to_timeval(timeout_ms, &timeout));
    if (ret > 0) {
        if (FD_ISSET(sock, &readset)) {
            uint8_t buffer;
            if (recv(sock, &buffer, 1, MSG_PEEK) <= 0) {
                // socket is readable, but reads zero bytes -- connection cleanly closed by FIN flag
                return 1;
            }
            ESP_LOGW(TAG, "esp_transport_derp_poll_connection_closed: unexpected data readable on socket=%d", sock);
        } else if (FD_ISSET(sock, &errset)) {
            int sock_errno = 0;
            uint32_t optlen = sizeof(sock_errno);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &sock_errno, &optlen);
            ESP_LOGD(TAG, "esp_transport_derp_poll_connection_closed select error %d, errno = %s, fd = %d", sock_errno, strerror(sock_errno), sock);
            if (sock_errno == ENOTCONN || sock_errno == ECONNRESET || sock_errno == ECONNABORTED) {
                // the three err codes above might be caused by connection termination by RTS flag
                // which we still assume as expected closing sequence of derp-transport connection
                return 1;
            }
            ESP_LOGE(TAG, "esp_transport_derp_poll_connection_closed: unexpected errno=%d on socket=%d", sock_errno, sock);
        }
        return -1; // indicates error: socket unexpectedly reads an actual data, or unexpected errno code
    }
    return ret;

}
