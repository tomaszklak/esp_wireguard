
#ifndef _ESP_TRANSPORT_DERP_H_
#define _ESP_TRANSPORT_DERP_H_

#include "esp_transport.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef enum derp_transport_frame_type {
    derp_frame_type_None            = 0x00,
    derp_frame_type_ServerKey       = 0x01,
    derp_frame_type_ClientInfo      = 0x02,
    derp_frame_type_ServerInfo      = 0x03,
    derp_frame_type_SendPacket      = 0x04,
    derp_frame_type_RecvPacket      = 0x05,
    derp_frame_type_KeepAlive       = 0x06,
    derp_frame_type_NotePreferred   = 0x07,
    derp_frame_type_PeerGone        = 0x08,
    derp_frame_type_PeerPersistent  = 0x09,
    derp_frame_type_WatchConns      = 0x10,
    derp_frame_type_ClosePeer       = 0x11,
    derp_frame_type_Ping            = 0x12,
    derp_frame_type_Pong            = 0x13,
    derp_frame_type_ControlMessage  = 0x14,
} derp_transport_frame_type_t;

typedef enum derp_transport_frame_channel {
    derp_frame_channel_Data         = 0x00,
    derp_frame_channel_Natter       = 0x01,
    derp_frame_channel_Cmder        = 0x02,
    derp_frame_channel_Nurse        = 0x03,
    derp_frame_channel_Unknown      = 0xFF,
} derp_transport_frame_channel_t;

/**
 * Derp transport configuration structure
 */
typedef struct {
    const char *user_agent;                 /*!< Derp user agent */
    const char *headers;                    /*!< Derp additional headers */
} esp_transport_derp_config_t;

/**
 * @brief      Create derp transport
 *
 * @return
 *  - transport
 *  - NULL
 */
esp_transport_handle_t esp_transport_derp_init(esp_transport_handle_t parent_handle);

/**
 * @brief               Set derp user-agent header
 *
 * @param t             derp transport handle
 * @param user_agent  user-agent string
 *
 * @return
 *      - ESP_OK on success
 *      - One of the error codes
 */
esp_err_t esp_transport_derp_set_user_agent(esp_transport_handle_t t, const char *user_agent);

/**
 * @brief               Set derp additional headers
 *
 * @param t             derp transport handle
 * @param headers  additional header strings each terminated with \r\n
 *
 * @return
 *      - ESP_OK on success
 *      - One of the error codes
 */
esp_err_t esp_transport_derp_set_headers(esp_transport_handle_t t, const char *headers);

/**
 * @brief               Set derp transport parameters
 *
 * @param t             derp transport handle
 * @param config        pointer to derp config structure
 *
 * @return
 *      - ESP_OK on success
 *      - One of the error codes
 */
esp_err_t esp_transport_derp_set_config(esp_transport_handle_t t, const esp_transport_derp_config_t *config);

/**
 * @brief               Sends derp raw message with custom frame_type and payload
 *
 * Note that generic esp_transport_write for derp handle sends
 * binary massages by default if size is > 0 and
 * ping message if message size is set to 0.
 * This API is provided to support explicit messages with arbitrary frame_type,
 * should it be PING, PONG or TEXT message with arbitrary data.
 *
 * @param[in]  t           Derp transport handle
 * @param[in]  frame_type  derp operation code
 * @param[in]  buffer      The buffer
 * @param[in]  len         The length
 * @param[in]  timeout_ms  The timeout milliseconds (-1 indicates block forever)
 *
 * @return
 *  - Number of bytes was written
 *  - (-1) if there are any errors, should check errno
 */
int esp_transport_derp_send_raw(esp_transport_handle_t t, derp_transport_frame_type_t frame_type, const char *b, int len, int timeout_ms);

/**
 * @brief               Returns derp frame_type for last received data
 *
 * @param t             derp transport handle
 *
 * @return
 *      - Received frame_type as enum
 */
derp_transport_frame_type_t esp_transport_derp_get_read_frame_type(esp_transport_handle_t t);

/**
 * @brief               Returns payload length of the last received data
 *
 * @param t             derp transport handle
 *
 * @return
 *      - Number of bytes in the payload
 */
int esp_transport_derp_get_read_payload_len(esp_transport_handle_t t);

/**
 * @brief               Polls the active connection for termination
 *
 * This API is typically used by the client to wait for clean connection closure
 * by derp server
 *
 * @param t             Derp transport handle
 * @param[in] timeout_ms The timeout milliseconds
 *
 * @return
 *      0 - no activity on read and error socket descriptor within timeout
 *      1 - Success: either connection terminated by FIN or the most common RST err codes
 *      -1 - Failure: Unexpected error code or socket is normally readable
 */
int esp_transport_derp_poll_connection_closed(esp_transport_handle_t t, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* _ESP_TRANSPORT_DERP_H_ */
