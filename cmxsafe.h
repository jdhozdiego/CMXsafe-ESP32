#include "libssh_esp32.h"
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <WiFiClient.h>
#include "settings.h"




typedef struct {
    int local_port;
    int forward_remote_port;
    bool high_bw;
} TaskParameters;


typedef struct {
    ssh_session my_ssh_session;
    int local_port;
    int forward_remote_port;
    bool high_bw;
} TaskParams_setup_ssh_port_forwarding;
// Define keepalive and timeout values

struct SSHKeepAliveTaskParams {
    ssh_session session;
    TaskHandle_t parentTaskHandle;
    TaskParameters parentParameters;
    uint32_t intervalMs; // Keep-alive interval in milliseconds
};

void libssh_begin();

typedef struct {
    ssh_session *my_ssh_session;
    ssh_message my_ssh_message;
    int local_port;
    int forward_remote_port;
    bool high_bw;
    TaskHandle_t *handler;
} chan_task_param;

typedef struct {
    const char *name;
    int local_port;
    int forward_remote_port;
    bool high_bw;
    TaskHandle_t handler;
    bool forwarded;
} PortConfig;

void msg_fwd_open_channel_task(void *pvParameters);
int msg_fwd_open_channel_callback(ssh_session session, ssh_message msg, void *userdata);
ssh_channel fwd_open_channel_callback(ssh_session session, void *userdata);
void global_forwarded_tcpip_callback (ssh_session session, ssh_message message, void *userdata);
ssh_channel forwarded_tcpip_callback(ssh_session my_ssh_session,
                                     const char *remote_host,
                                     int forward_remote_port,
                                     const char *local_host,
                                     int local_port,
                                     void *userdata);

bool setup_ssh_port_forwarding(ssh_session my_ssh_session, int local_port, int forward_remote_port, bool high_bw);
void ssh_port_forwarding_task(void *parameter);


