
#ifndef _ESP_DERP_CLIENT_H_
#define _ESP_DERP_CLIENT_H_


#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "esp_err.h"
#include "esp_event.h"
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct esp_derp_client *esp_derp_client_handle_t;

ESP_EVENT_DECLARE_BASE(DERP_EVENTS);         // declaration of the task events family

/**
 * @brief Derp Client events id
 */
typedef enum {
    DERP_EVENT_ANY = -1,
    DERP_EVENT_ERROR = 0,      /*!< This event occurs when there are any errors during execution */
    DERP_EVENT_CONNECTED,      /*!< Once the DERP has been connected to the server, no data exchange has been performed */
    DERP_EVENT_DISCONNECTED,   /*!< The connection has been disconnected */
    DERP_EVENT_DATA,           /*!< When receiving data from the server, possibly multiple portions of the packet */
    DERP_EVENT_CLOSED,         /*!< The connection has been closed cleanly */
    DERP_EVENT_MAX
} esp_derp_event_id_t;

/**
 * @brief Derp event data
 */
typedef struct {
    const char *data_ptr;                   /*!< Data pointer */
    int data_len;                           /*!< Data length */
    const char* peer_pubkey;                /*!< Peer public key (base64 encoded) */
    int peer_pubkey_len;                    /*!< Peer public key length (not necessary, constant) */
    uint8_t frame_type;                     /*!< Received frame_type */
    uint8_t data_frame_channel;             /*!< Received frame_channel */
    esp_derp_client_handle_t client;        /*!< esp_derp_client_handle_t context */
    void *user_context;                     /*!< user_data context, from esp_derp_client_config_t user_data */
    int payload_len;                        /*!< Total payload length, payloads exceeding buffer will be posted through multiple events */
    int payload_offset;                     /*!< Actual offset for the data associated with this event */
} esp_derp_event_data_t;

/**
 * @brief Derp Client transport
 */
typedef enum {
    DERP_TRANSPORT_UNKNOWN = 0x0,  /*!< Transport unknown */
    DERP_TRANSPORT_OVER_TCP,       /*!< Transport over tcp */
    DERP_TRANSPORT_OVER_SSL,       /*!< Transport over ssl */
} esp_derp_transport_t;

/**
 * @brief Derp client setup configuration
 */
typedef struct {
    const char                  *host;                      /*!< Domain or IP as string */
    int                         port;                       /*!< Port to connect, default depend on esp_derp_transport_t (default 8765) */
    const char*                 public_key;                 /*!< Public key (base64 encoded) or DERP server */
    bool                        disable_auto_reconnect;     /*!< Disable the automatic reconnect function when disconnected */

    int                         task_prio;                  /*!< Derp task priority */
    int                         task_stack;                 /*!< Derp task stack */
    int                         buffer_size;                /*!< Derp buffer size */

    const char                  *cert_pem;                  /*!< Pointer to certificate data in PEM or DER format for server verify (with SSL), default is NULL, not required to verify the server. PEM-format must have a terminating NULL-character. DER-format requires the length to be passed in cert_len. */
    size_t                      cert_len;                   /*!< Length of the buffer pointed to by cert_pem. May be 0 for null-terminated pem */
    const char                  *client_cert;               /*!< Pointer to certificate data in PEM or DER format for SSL mutual authentication, default is NULL, not required if mutual authentication is not needed. If it is not NULL, also `client_key` has to be provided. PEM-format must have a terminating NULL-character. DER-format requires the length to be passed in client_cert_len. */
    size_t                      client_cert_len;            /*!< Length of the buffer pointed to by client_cert. May be 0 for null-terminated pem */
    const char                  *client_key;                /*!< Pointer to private key data in PEM or DER format for SSL mutual authentication, default is NULL, not required if mutual authentication is not needed. If it is not NULL, also `client_cert` has to be provided. PEM-format must have a terminating NULL-character. DER-format requires the length to be passed in client_key_len */
    size_t                      client_key_len;             /*!< Length of the buffer pointed to by client_key_pem. May be 0 for null-terminated pem */
    bool                        use_global_ca_store;        /*!< Use a global ca_store for all the connections in which this bool is set. */
    bool                        skip_cert_common_name_check;/*!< Skip any validation of server certificate CN field */

    esp_derp_transport_t        transport;                  /*!< Derp transport type, see `esp_derp_transport_t */
    const char                  *user_agent;                /*!< Derp user-agent */
    const char                  *headers;                   /*!< Derp additional headers */

    struct ifreq                *if_name;                   /*!< The name of interface for data to go through. Use the default interface without setting */
} esp_derp_client_config_t;

/**
 * @brief      Start a Derp session
 *             This function must be the first function to call,
 *             and it returns a esp_derp_client_handle_t that you must use as input to other functions in the interface.
 *             This call MUST have a corresponding call to esp_derp_client_destroy when the operation is complete.
 *
 * @param[in]  config  The configuration
 *
 * @return
 *     - `esp_derp_client_handle_t`
 *     - NULL if any errors
 */
esp_derp_client_handle_t esp_derp_client_init(const esp_derp_client_config_t *config);

/**
 * @brief      Open the Derp connection
 *
 * @param[in]  client  The client
 *
 * @return     esp_err_t
 */
esp_err_t esp_derp_client_start(esp_derp_client_handle_t client);

/**
 * @brief      Stops the Derp connection without derp closing handshake
 *
 * This API stops ws client and closes TCP connection directly without sending
 * close frames. It is a good practice to close the connection in a clean way
 * using esp_derp_client_close().
 *
 *  Notes:
 *  - Cannot be called from the derp event handler
 *
 * @param[in]  client  The client
 *
 * @return     esp_err_t
 */
esp_err_t esp_derp_client_stop(esp_derp_client_handle_t client);

/**
 * @brief      Destroy the Derp connection and free all resources.
 *             This function must be the last function to call for an session.
 *             It is the opposite of the esp_derp_client_init function and must be called with the same handle as input that a esp_derp_client_init call returned.
 *             This might close all connections this handle has used.
 *
 *  Notes:
 *  - Cannot be called from the derp event handler
 *
 * @param[in]  client  The client
 *
 * @return     esp_err_t
 */
esp_err_t esp_derp_client_destroy(esp_derp_client_handle_t client);

/**
 * @brief      Generic write data to the Derp connection; defaults to binary send
 *
 * @param[in]  client  The client
 * @param[in]  data    The data
 * @param[in]  len     The length
 * @param[in]  timeout Write data timeout in RTOS ticks
 *
 * @return
 *     - Number of data was sent
 *     - (-1) if any errors
 */
int esp_derp_client_send(esp_derp_client_handle_t client, const char *data, int len, TickType_t timeout);

/**
 * @brief      Check the Derp client connection state
 *
 * @param[in]  client  The client handle
 *
 * @return
 *     - true
 *     - false
 */
bool esp_derp_client_is_connected(esp_derp_client_handle_t client);

/**
 * @brief Register the Derp Events
 *
 * @param client            The client handle
 * @param event             The event id
 * @param event_handler     The callback function
 * @param event_handler_arg User context
 * @return esp_err_t
 */
esp_err_t esp_derp_register_events(esp_derp_client_handle_t client,
                                        esp_derp_event_id_t event,
                                        esp_event_handler_t event_handler,
                                        void *event_handler_arg);

#ifdef __cplusplus
}
#endif

#endif
