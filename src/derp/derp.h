
#ifndef _DERP_H_
#define _DERP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "lwip/ip_addr.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_websocket_client.h"
#include "esp_event.h"

#define MAX_ALLOWED_PEERS 10


typedef enum {
    derp_state_Init,
    derp_state_Connecting,
    derp_state_Connected,
} derp_state_t;

typedef struct derp_endpoint {
	QueueHandle_t ingress_queue;
    QueueHandle_t egress_queue;
} derp_endpoint_t;

typedef struct ip_endpoint {
	ip_addr_t endpoint_ip;
	u16_t endport_port;
} ip_endpoint_t;

typedef union wireguardif_endpoint {
	ip_endpoint_t ip_endpoint;
	derp_endpoint_t derp_endpoint;
} universal_endpoint;

typedef struct {
    // TODO enable hostname resolution ..?
    /// Hostname of the server
    // const char* hostname;
    /// IP address of the server
    ip_addr_t ipv4;
    /// Port on which server listens to relay requests
    uint16_t relay_port;
    /// Server public key
    const uint8_t* public_key;
} derp_server_t;

typedef struct { 
    /// Secret key of local node which is used for encryption/decryption of messages to other nodes
    const uint8_t* secret_key;
    /// List of potential Derp servers
    derp_server_t server;
    // TODO this should be updated to a list of allowed peers (when implementing mesh)
    /// Remote peer (list) that we accept traffic from
    const uint8_t* allowed_pk[MAX_ALLOWED_PEERS];
} derp_config_t;

typedef struct {
    derp_config_t* config;
    TaskHandle_t task_handle;
    // derp_task <-> netif
    derp_endpoint_t derp_endpoint;
    // ws_event_handler -> derp_task
    QueueHandle_t rx_queue;
    derp_state_t state;
    esp_websocket_client_handle_t ws_handle;
} derp_ctx_t;


esp_err_t derp_init(derp_config_t* config, derp_ctx_t* ctx);
esp_err_t derp_destroy(derp_ctx_t* ctx);
esp_err_t derp_start(derp_ctx_t* ctx);
esp_err_t derp_stop(derp_ctx_t* ctx);
bool derp_is_running(derp_ctx_t* ctx);
bool derp_is_connected(derp_ctx_t* ctx);

bool derp_is_endpoint_derp(const wireguard_config_t *config) {
    return config->derp_config != NULL;
}


#ifdef __cplusplus
}
#endif

#endif /* _DERP_H_ */