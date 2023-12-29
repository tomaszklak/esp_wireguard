
#include <stdio.h>

#include "esp_derp_client.h"
#include "esp_transport.h"
#include "esp_transport_tcp.h"
#include "esp_transport_ssl.h"
#include "esp_transport_derp.h"
/* using uri parser */
#include "http_parser.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "DERP_CLIENT";

#define DERP_TCP_DEFAULT_PORT      (8765)
#define DERP_SSL_DEFAULT_PORT      (8765)
#define DERP_BUFFER_SIZE_BYTE      (1420)
#define DERP_RECONNECT_TIMEOUT_MS  (10*1000)
#define DERP_TASK_PRIORITY         (5)
#define DERP_TASK_STACK            (4*1420)
#define DERP_NETWORK_TIMEOUT_MS    (10*1000)
#define DERP_EVENT_QUEUE_SIZE      (1)


#define ESP_DERP_CLIENT_MEM_CHECK(TAG, a, action) if (!(a)) {                                         \
        ESP_LOGE(TAG,"%s(%d): %s", __FUNCTION__, __LINE__, "Memory exhausted");                     \
        action;                                                                                     \
        }

#define ESP_DERP_CLIENT_ERR_OK_CHECK(TAG, err, action)  { \
        esp_err_t _esp_derp_err_to_check = err;           \
        if (_esp_derp_err_to_check != ESP_OK) {           \
            ESP_LOGE(TAG,"%s(%d): Expected ESP_OK; reported: %d", __FUNCTION__, __LINE__, _esp_derp_err_to_check); \
            action;                                     \
            }                                           \
        }

#define ESP_DERP_CLIENT_STATE_CHECK(TAG, a, action) if ((a->state) < DERP_STATE_INIT) {                                         \
        ESP_LOGE(TAG,"%s(%d): %s", __FUNCTION__, __LINE__, "Derp already stop"); \
        action;                                                                                     \
        }

ESP_EVENT_DEFINE_BASE(DERP_EVENTS);

typedef struct {
    int                         task_stack;
    int                         task_prio;
    char                        *host;
    int                         port;
    bool                        auto_reconnect;
    void                        *user_context;
    int                         network_timeout_ms;
    char                        *user_agent;
    char                        *headers;
} derp_config_storage_t;

typedef enum {
    DERP_STATE_ERROR = -1,
    DERP_STATE_UNKNOW = 0,
    DERP_STATE_INIT,
    DERP_STATE_CONNECTED,
    DERP_STATE_WAIT_TIMEOUT,
    DERP_STATE_CLOSING,
} derp_client_state_t;

struct esp_derp_client {
    esp_event_loop_handle_t     event_handle;
    TaskHandle_t                task_handle;
    esp_transport_list_handle_t transport_list;
    esp_transport_handle_t      transport;
    derp_config_storage_t       *config;
    derp_client_state_t         state;
    uint64_t                    reconnect_tick_ms;
    int                         wait_timeout_ms;
    int                         auto_reconnect;
    bool                        run;
    EventGroupHandle_t          status_bits;
    xSemaphoreHandle            lock;
    char                        *rx_buffer;
    char                        *tx_buffer;
    int                         buffer_size;
    derp_transport_frame_type_t     last_frame_type;
    char*                           last_peer_pubkey;
    derp_transport_frame_channel_t  last_frame_channel;
    int                         payload_len;
    int                         payload_offset;
    struct ifreq                *if_name;
};

static uint64_t _tick_get_ms(void)
{
    return esp_timer_get_time()/1000;
}

static esp_err_t esp_derp_client_dispatch_event(esp_derp_client_handle_t client,
        esp_derp_event_id_t event,
        const char *data,
        int data_len)
{
    esp_err_t err;
    esp_derp_event_data_t event_data;

    event_data.client = client;
    event_data.user_context = client->config->user_context;
    event_data.data_ptr = data;
    event_data.data_len = data_len;
    event_data.frame_type = client->last_frame_type;
    event_data.payload_len = client->payload_len;
    event_data.payload_offset = client->payload_offset;

    event_data.peer_pubkey = client->last_peer_pubkey;
    event_data.peer_pubkey_len = PUBKEY_LEN;
    event_data.data_frame_channel = client->last_frame_channel;

    if ((err = esp_event_post_to(client->event_handle,
                                 DERP_EVENTS, event,
                                 &event_data,
                                 sizeof(esp_derp_event_data_t),
                                 portMAX_DELAY)) != ESP_OK) {
        return err;
    }
    return esp_event_loop_run(client->event_handle, 0);
}

static esp_err_t esp_derp_client_abort_connection(esp_derp_client_handle_t client)
{
    ESP_DERP_CLIENT_STATE_CHECK(TAG, client, return ESP_FAIL);
    esp_transport_close(client->transport);

    if (client->config->auto_reconnect) {
        client->wait_timeout_ms = DERP_RECONNECT_TIMEOUT_MS;
        client->reconnect_tick_ms = _tick_get_ms();
        ESP_LOGI(TAG, "Reconnect after %d ms", client->wait_timeout_ms);
    }
    client->state = DERP_STATE_WAIT_TIMEOUT;
    esp_derp_client_dispatch_event(client, DERP_EVENT_DISCONNECTED, NULL, 0);
    return ESP_OK;
}

static esp_err_t esp_derp_client_set_config(esp_derp_client_handle_t client, const esp_derp_client_config_t *config)
{
    derp_config_storage_t *cfg = client->config;
    cfg->task_prio = config->task_prio;
    if (cfg->task_prio <= 0) {
        cfg->task_prio = DERP_TASK_PRIORITY;
    }

    cfg->task_stack = config->task_stack;
    if (cfg->task_stack == 0) {
        cfg->task_stack = DERP_TASK_STACK;
    }

    if (config->host) {
        cfg->host = strdup(config->host);
        ESP_DERP_CLIENT_MEM_CHECK(TAG, cfg->host, return ESP_ERR_NO_MEM);
    }

    if (config->port) {
        cfg->port = config->port;
    }

    if (config->user_agent) {
        free(cfg->user_agent);
        cfg->user_agent = strdup(config->user_agent);
        ESP_DERP_CLIENT_MEM_CHECK(TAG, cfg->user_agent, return ESP_ERR_NO_MEM);
    }

    if (config->headers) {
        free(cfg->headers);
        cfg->headers = strdup(config->headers);
        ESP_DERP_CLIENT_MEM_CHECK(TAG, cfg->headers, return ESP_ERR_NO_MEM);
    }

    cfg->network_timeout_ms = DERP_NETWORK_TIMEOUT_MS;
    cfg->user_context = config->user_context;
    cfg->auto_reconnect = true;
    if (config->disable_auto_reconnect) {
        cfg->auto_reconnect = false;
    }

    return ESP_OK;
}

static esp_err_t esp_derp_client_destroy_config(esp_derp_client_handle_t client)
{
    if (client == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    derp_config_storage_t *cfg = client->config;
    if (client->config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    free(cfg->host);
    free(cfg->user_agent);
    free(cfg->headers);
    memset(cfg, 0, sizeof(derp_config_storage_t));
    free(client->config);
    client->config = NULL;
    return ESP_OK;
}

static esp_err_t set_derp_transport_optional_settings(esp_derp_client_handle_t client, const char *scheme)
{
    esp_transport_handle_t trans = esp_transport_list_get_transport(client->transport_list, scheme);
    if (trans) {
        const esp_transport_derp_config_t config = {
                .user_agent = client->config->user_agent,
                .headers = client->config->headers
        };
        return esp_transport_derp_set_config(trans, &config);
    }
    return ESP_ERR_INVALID_ARG;
}

esp_derp_client_handle_t esp_derp_client_init(const esp_derp_client_config_t *config)
{
    esp_derp_client_handle_t client = calloc(1, sizeof(struct esp_derp_client));
    ESP_DERP_CLIENT_MEM_CHECK(TAG, client, return NULL);

    esp_event_loop_args_t event_args = {
        .queue_size = DERP_EVENT_QUEUE_SIZE,
        .task_name = NULL // no task will be created
    };

    if (esp_event_loop_create(&event_args, &client->event_handle) != ESP_OK) {
        ESP_LOGE(TAG, "Error create event handler for derp client");
        free(client);
        return NULL;
    }

    if (config->if_name) {
        client->if_name = calloc(1, sizeof(struct ifreq) + 1);
        ESP_DERP_CLIENT_MEM_CHECK(TAG, client->if_name, goto _derp_init_fail);
        memcpy(client->if_name, config->if_name, sizeof(struct ifreq));
    }

    client->lock = xSemaphoreCreateRecursiveMutex();
    ESP_DERP_CLIENT_MEM_CHECK(TAG, client->lock, goto _derp_init_fail);

    client->config = calloc(1, sizeof(derp_config_storage_t));
    ESP_DERP_CLIENT_MEM_CHECK(TAG, client->config, goto _derp_init_fail);

    client->transport_list = esp_transport_list_init();
    ESP_DERP_CLIENT_MEM_CHECK(TAG, client->transport_list, goto _derp_init_fail);

    esp_transport_handle_t tcp = esp_transport_tcp_init();
    ESP_DERP_CLIENT_MEM_CHECK(TAG, tcp, goto _derp_init_fail);

    esp_transport_set_default_port(tcp, DERP_TCP_DEFAULT_PORT);
    esp_transport_list_add(client->transport_list, tcp, "_tcp"); // need to save to transport list, for cleanup
    esp_transport_tcp_set_keep_alive(tcp, &client->keep_alive_cfg);
    esp_transport_tcp_set_interface_name(tcp, client->if_name);

    esp_transport_handle_t derp = esp_transport_derp_init(tcp);
    ESP_DERP_CLIENT_MEM_CHECK(TAG, derp, goto _derp_init_fail);

    esp_transport_set_default_port(derp, DERP_TCP_DEFAULT_PORT);
    esp_transport_list_add(client->transport_list, derp, "derp");
    if (config->transport == DERP_TRANSPORT_OVER_TCP) {
        asprintf(&client->config->scheme, "derp");
        ESP_DERP_CLIENT_MEM_CHECK(TAG, client->config->scheme, goto _derp_init_fail);
    }

    esp_transport_handle_t ssl = esp_transport_ssl_init();
    ESP_DERP_CLIENT_MEM_CHECK(TAG, ssl, goto _derp_init_fail);

    esp_transport_set_default_port(ssl, DERP_SSL_DEFAULT_PORT);
    esp_transport_list_add(client->transport_list, ssl, "_ssl"); // need to save to transport list, for cleanup
    if (config->use_global_ca_store == true) {
        esp_transport_ssl_enable_global_ca_store(ssl);
    } else if (config->cert_pem) {
        if (!config->cert_len) {
            esp_transport_ssl_set_cert_data(ssl, config->cert_pem, strlen(config->cert_pem));
        } else {
            esp_transport_ssl_set_cert_data_der(ssl, config->cert_pem, config->cert_len);
        }
    }
    if (config->client_cert) {
        if (!config->client_cert_len) {
            esp_transport_ssl_set_client_cert_data(ssl, config->client_cert, strlen(config->client_cert));
        } else {
            esp_transport_ssl_set_client_cert_data_der(ssl, config->client_cert, config->client_cert_len);
        }
    }
    if (config->client_key) {
        if (!config->client_key_len) {
            esp_transport_ssl_set_client_key_data(ssl, config->client_key, strlen(config->client_key));
        } else {
            esp_transport_ssl_set_client_key_data_der(ssl, config->client_key, config->client_key_len);
        }
    }
    if (config->skip_cert_common_name_check) {
        esp_transport_ssl_skip_common_name_check(ssl);
    }

    esp_transport_handle_t derps = esp_transport_derp_init(ssl);
    ESP_DERP_CLIENT_MEM_CHECK(TAG, derps, goto _derp_init_fail);

    esp_transport_set_default_port(derps, DERP_SSL_DEFAULT_PORT);

    esp_transport_list_add(client->transport_list, derps, "derps");
    if (config->transport == DERP_TRANSPORT_OVER_SSL) {
        asprintf(&client->config->scheme, "derps");
        ESP_DERP_CLIENT_MEM_CHECK(TAG, client->config->scheme, goto _derp_init_fail);
    }

    if (esp_derp_client_set_config(client, config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set the configuration");
        goto _derp_init_fail;
    }

    if (client->config->scheme == NULL) {
        asprintf(&client->config->scheme, "derp");
        ESP_DERP_CLIENT_MEM_CHECK(TAG, client->config->scheme, goto _derp_init_fail);
    }

    ESP_DERP_CLIENT_ERR_OK_CHECK(TAG, set_derp_transport_optional_settings(client, "derp"), goto _derp_init_fail;)
    ESP_DERP_CLIENT_ERR_OK_CHECK(TAG, set_derp_transport_optional_settings(client, "derps"), goto _derp_init_fail;)

    client->reconnect_tick_ms = _tick_get_ms();

    int buffer_size = config->buffer_size;
    if (buffer_size <= 0) {
        buffer_size = DERP_BUFFER_SIZE_BYTE;
    }
    client->rx_buffer = malloc(buffer_size);
    ESP_DERP_CLIENT_MEM_CHECK(TAG, client->rx_buffer, {
        goto _derp_init_fail;
    });
    client->tx_buffer = malloc(buffer_size);
    ESP_DERP_CLIENT_MEM_CHECK(TAG, client->tx_buffer, {
        goto _derp_init_fail;
    });
    client->status_bits = xEventGroupCreate();
    ESP_DERP_CLIENT_MEM_CHECK(TAG, client->status_bits, {
        goto _derp_init_fail;
    });

    client->buffer_size = buffer_size;
    return client;

_derp_init_fail:
    esp_derp_client_destroy(client);
    return NULL;
}

esp_err_t esp_derp_client_destroy(esp_derp_client_handle_t client)
{
    if (client == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (client->run) {
        esp_derp_client_stop(client);
    }
    if (client->event_handle) {
        esp_event_loop_delete(client->event_handle);
    }
    if (client->if_name) {
        free(client->if_name);
    }
    esp_derp_client_destroy_config(client);
    esp_transport_list_destroy(client->transport_list);
    vQueueDelete(client->lock);
    free(client->tx_buffer);
    free(client->rx_buffer);
    if (client->status_bits) {
        vEventGroupDelete(client->status_bits);
    }
    free(client);
    client = NULL;
    return ESP_OK;
}

static esp_err_t esp_derp_client_recv(esp_derp_client_handle_t client)
{
    int rlen;
    client->payload_offset = 0;
    do {
        rlen = esp_transport_read(client->transport, client->rx_buffer, client->buffer_size, client->config->network_timeout_ms);
        if (rlen < 0) {
            ESP_LOGE(TAG, "Error read data");
            return ESP_FAIL;
        }
        client->payload_len = esp_transport_derp_get_read_payload_len(client->transport);
        client->last_frame_type = esp_transport_derp_get_read_frame_type(client->transport);

        client->last_frame_channel = esp_transport_derp_get_read_frame_channel(client->transport);
        client->last_peer_pubkey = esp_transport_derp_get_read_peer_pubkey(client->transport);

        if (rlen == 0) {
            ESP_LOGV(TAG, "esp_transport_read timeouts");
            return ESP_OK;
        }

        esp_derp_client_dispatch_event(client, DERP_EVENT_DATA, client->rx_buffer, rlen);

        client->payload_offset += rlen;
    } while (client->payload_offset < client->payload_len);

    return ESP_OK;
}

static int esp_derp_client_send_with_frame_type(esp_derp_client_handle_t client,derp_transport_frame_type_t frame_type, const uint8_t *data, int len, TickType_t timeout);

static void esp_derp_client_task(void *pv)
{
    const int lock_timeout = portMAX_DELAY;
    esp_derp_client_handle_t client = (esp_derp_client_handle_t) pv;
    client->run = true;

    //get transport by scheme
    client->transport = esp_transport_list_get_transport(client->transport_list, client->config->scheme);

    if (client->transport == NULL) {
        ESP_LOGE(TAG, "There are no transports valid, stop derp client");
        client->run = false;
    }
    //default port
    if (client->config->port == 0) {
        client->config->port = esp_transport_get_default_port(client->transport);
    }

    client->state = DERP_STATE_INIT;
    xEventGroupClearBits(client->status_bits, STOPPED_BIT);
    int read_select = 0;
    while (client->run) {
        if (xSemaphoreTakeRecursive(client->lock, lock_timeout) != pdPASS) {
            ESP_LOGE(TAG, "Failed to lock derp-client tasks, exiting the task...");
            break;
        }
        switch ((int)client->state) {
            case DERP_STATE_INIT:
                if (client->transport == NULL) {
                    ESP_LOGE(TAG, "There are no transport");
                    client->run = false;
                    break;
                }
                if (esp_transport_connect(client->transport,
                                          client->config->host,
                                          client->config->port,
                                          client->config->network_timeout_ms) < 0) {
                    ESP_LOGE(TAG, "Error transport connect");
                    esp_derp_client_abort_connection(client);
                    break;
                }
                ESP_LOGD(TAG, "Transport connected to %s://%s:%d", client->config->scheme, client->config->host, client->config->port);

                client->state = DERP_STATE_CONNECTED;
                esp_derp_client_dispatch_event(client, DERP_EVENT_CONNECTED, NULL, 0);

                break;
            case DERP_STATE_CONNECTED:
                if (read_select == 0) {
                    ESP_LOGV(TAG, "Read poll timeout: skipping esp_transport_read()...");
                    break;
                }

                if (esp_derp_client_recv(client) == ESP_FAIL) {
                    ESP_LOGE(TAG, "Error receive data");
                    esp_derp_client_abort_connection(client);
                    break;
                }
                break;
            case DERP_STATE_WAIT_TIMEOUT:
                if (!client->config->auto_reconnect) {
                    client->run = false;
                    break;
                }
                if (_tick_get_ms() - client->reconnect_tick_ms > client->wait_timeout_ms) {
                    client->state = DERP_STATE_INIT;
                    client->reconnect_tick_ms = _tick_get_ms();
                    ESP_LOGD(TAG, "Reconnecting...");
                }
                break;
            case DERP_STATE_CLOSING:
                break;
            default:
                ESP_LOGD(TAG, "Client run iteration in a default state: %d", client->state);
                break;
        }
        xSemaphoreGiveRecursive(client->lock);
        if (DERP_STATE_CONNECTED == client->state) {
            read_select = esp_transport_poll_read(client->transport, 1000); //Poll every 1000ms
            if (read_select < 0) {
                ESP_LOGE(TAG, "Network error: esp_transport_poll_read() returned %d, errno=%d", read_select, errno);
                esp_derp_client_abort_connection(client);
            }
        } else if (DERP_STATE_WAIT_TIMEOUT == client->state) {
            // waiting for reconnecting...
            vTaskDelay(client->wait_timeout_ms / 2 / portTICK_RATE_MS);
        } else if (DERP_STATE_CLOSING == client->state) {
            ESP_LOGD(TAG, " Waiting for TCP connection to be closed by the server");
            int ret = esp_transport_derp_poll_connection_closed(client->transport, 1000);
            if (ret == 0) {
                // still waiting
                break;
            }
            if (ret < 0) {
                ESP_LOGW(TAG, "Connection terminated while waiting for clean TCP close");
            }
            client->run = false;
            client->state = DERP_STATE_UNKNOW;
            esp_derp_client_dispatch_event(client, DERP_EVENT_CLOSED, NULL, 0);
            break;
        }
    }

    esp_transport_close(client->transport);
    xEventGroupSetBits(client->status_bits, STOPPED_BIT);
    client->state = DERP_STATE_UNKNOW;
    vTaskDelete(NULL);
}

esp_err_t esp_derp_client_start(esp_derp_client_handle_t client)
{
    if (client == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (client->state >= DERP_STATE_INIT) {
        ESP_LOGE(TAG, "The client has started");
        return ESP_FAIL;
    }
    if (xTaskCreate(esp_derp_client_task, "derp_task", client->config->task_stack, client, client->config->task_prio, &client->task_handle) != pdTRUE) {
        ESP_LOGE(TAG, "Error create derp task");
        return ESP_FAIL;
    }
    xEventGroupClearBits(client->status_bits, STOPPED_BIT);
    return ESP_OK;
}

esp_err_t esp_derp_client_stop(esp_derp_client_handle_t client)
{
    if (client == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!client->run) {
        ESP_LOGW(TAG, "Client was not started");
        return ESP_FAIL;
    }

    /* A running client cannot be stopped from the derp task/event handler */
    TaskHandle_t running_task = xTaskGetCurrentTaskHandle();
    if (running_task == client->task_handle) {
        ESP_LOGE(TAG, "Client cannot be stopped from derp task");
        return ESP_FAIL;
    }


    client->run = false;
    xEventGroupWaitBits(client->status_bits, STOPPED_BIT, false, true, portMAX_DELAY);
    client->state = DERP_STATE_UNKNOW;
    return ESP_OK;
}

int esp_derp_client_send(esp_derp_client_handle_t client, const char *data, int len, TickType_t timeout)
{
    return esp_derp_client_send_with_frame_type(client, derp_frame_type_SendPacket, (const uint8_t *)data, len, timeout);
}

static int esp_derp_client_send_with_frame_type(esp_derp_client_handle_t client, derp_transport_frame_type_t frame_type, const uint8_t *data, int len, TickType_t timeout)
{
    int need_write = len;
    int wlen = 0, widx = 0;
    int ret = ESP_FAIL;

    if (client == NULL || len < 0) {
        ESP_LOGE(TAG, "Invalid arguments");
        return ESP_FAIL;
    }

    if (xSemaphoreTakeRecursive(client->lock, timeout) != pdPASS) {
        ESP_LOGE(TAG, "Could not lock derp-client within %d timeout", timeout);
        return ESP_FAIL;
    }

    if (!esp_derp_client_is_connected(client)) {
        ESP_LOGE(TAG, "Derp client is not connected");
        goto unlock_and_return;
    }

    if (client->transport == NULL) {
        ESP_LOGE(TAG, "Invalid transport");
        goto unlock_and_return;
    }
    uint32_t current_frame_type = frame_type;
    while (widx < len || current_frame_type) { 
        if (need_write > client->buffer_size) {
            need_write = client->buffer_size;
        }
        memcpy(client->tx_buffer, data + widx, need_write);
        // send with derp specific way and specific frame_type
        wlen = esp_transport_derp_send_raw(client->transport, current_frame_type, (char *)client->tx_buffer, need_write,
                                        (timeout==portMAX_DELAY)? -1 : timeout * portTICK_PERIOD_MS);
        if (wlen < 0 || (wlen == 0 && need_write != 0)) {
            ret = wlen;
            ESP_LOGE(TAG, "Network error: esp_transport_write() returned %d, errno=%d", ret, errno);
            esp_derp_client_abort_connection(client);
            goto unlock_and_return;
        }
        current_frame_type = 0;
        widx += wlen;
        need_write = len - widx;

    }
    ret = widx;
unlock_and_return:
    xSemaphoreGiveRecursive(client->lock);
    return ret;
}

bool esp_derp_client_is_connected(esp_derp_client_handle_t client)
{
    if (client == NULL) {
        return false;
    }
    return client->state == DERP_STATE_CONNECTED;
}

esp_err_t esp_derp_register_events(esp_derp_client_handle_t client,
                                        esp_derp_event_id_t event,
                                        esp_event_handler_t event_handler,
                                        void *event_handler_arg)
{
    if (client == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return esp_event_handler_register_with(client->event_handle, DERP_EVENTS, event, event_handler, event_handler_arg);
}
