
#include "derp.h"


static void derp_event_handler(void* handler_args, esp_event_base_t base, int32_t event_id, void* event_data);
static void derp_task(void *pvParameters);
static void derp_send_packet();
static void derp_parse_packet();


esp_err_t derp_init(derp_config_t* config, derp_ctx_t* ctx) {
    esp_websocket_client_config_t websocket_cfg = { 0x00 };
    websocket_cfg.transport = WEBSOCKET_TRANSPORT_OVER_TCP;
    websocket_cfg.disable_auto_reconnect = false;
    websocket_cfg.user_agent = "telio";

    // const char                  *host;                      /*!< Domain or IP as string */
    // int                         port;                       /*!< Port to connect, default depend on esp_websocket_transport_t (80 or 443) */
    // const char                  *path;                      /*!< HTTP Path, if not set, default is `/` */
    // void                        *user_context;              /*!< HTTP user data context */
    // int                         task_prio;                  /*!< Websocket task priority */
    // int                         task_stack;                 /*!< Websocket task stack */
    // int                         buffer_size;                /*!< Websocket buffer size */
    // const char                  *subprotocol;               /*!< Websocket subprotocol */
    // const char                  *headers;                   /*!< Websocket additional headers */
    // int                         pingpong_timeout_sec;       /*!< Period before connection is aborted due to no PONGs received */
    // bool                        disable_pingpong_discon;    /*!< Disable auto-disconnect due to no PONG received within pingpong_timeout_sec */
    // bool                        keep_alive_enable;          /*!< Enable keep-alive timeout */
    // int                         keep_alive_idle;            /*!< Keep-alive idle time. Default is 5 (second) */
    // int                         keep_alive_interval;        /*!< Keep-alive interval time. Default is 5 (second) */
    // int                         keep_alive_count;           /*!< Keep-alive packet retry send count. Default is 3 counts */
    // size_t                      ping_interval_sec;          /*!< Websocket ping interval, defaults to 10 seconds if not set */
    // struct ifreq                *if_name;                   /*!< The name of interface for data to go through. Use the default interface without setting */

    ctx->ws_handle = esp_websocket_client_init(&websocket_cfg);
    esp_websocket_register_events(ctx->ws_handle, WEBSOCKET_EVENT_ANY, ws_event_handler, (void*)ctx->ws_handle);
}

esp_err_t derp_destroy(derp_ctx_t* ctx) {
    esp_websocket_client_destroy(ctx->ws_handle);
}

esp_err_t derp_start(derp_ctx_t* ctx) {
    esp_websocket_client_start(ctx->ws_handle);
}

esp_err_t derp_stop(derp_ctx_t* ctx) {
    esp_websocket_client_close(ctx->ws_handle, portMAX_DELAY);
}

static void derp_event_handler(void* handler_args, esp_event_base_t base, int32_t event_id, void* event_data) {
    esp_websocket_event_data_t* data = (esp_websocket_event_data_t*)event_data;
    derp_ctx_t* derp_ctx = (derp_ctx_t*)handler_args;

    switch ((esp_websocket_event_id_t)event_id) {
        case WEBSOCKET_EVENT_CONNECTED:
            ESP_LOGI(TAG, "WEBSOCKET_EVENT_CONNECTED");
            // 1. read_server_key
            // 2. write_client_key
            break;
        case WEBSOCKET_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "WEBSOCKET_EVENT_DISCONNECTED");
            break;
        case WEBSOCKET_EVENT_DATA:
            ESP_LOGI(TAG, "WEBSOCKET_EVENT_DATA");
            ESP_LOGI(TAG, "Received frame_type=%d", data->frame_type);
            if (data->frame_type == WSop_close && data->data_len == 2) {
                ESP_LOGW(TAG, "Received closed message with code=%d", 256 * data->data_ptr[0] + data->data_ptr[1]);
            } else {
                ESP_LOGW(TAG, "Received=%.*s", data->data_len, (char *)data->data_ptr);
            }
            ESP_LOGW(TAG, "Total payload length=%d, data_len=%d, current payload offset=%d\r\n", data->payload_len, data->data_len, data->payload_offset);

            xTimerReset(shutdown_signal_timer, portMAX_DELAY);
            break;
        case WEBSOCKET_EVENT_ERROR:
            ESP_LOGI(TAG, "WEBSOCKET_EVENT_ERROR");
            break;
    }
}

static void derp_task(void *pvParameters) {
    // 1. Wait on rx_queue, parse derp headers, than send to ingress_queue
    // 2. Wait on egress_queue, add derp headers, than esp_websocket_client_send
}
