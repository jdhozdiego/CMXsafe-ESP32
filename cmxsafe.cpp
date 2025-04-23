/**********************************************************************
  Filename    : CMXsafe security module
  Description : This is the secure module for ESP32, able to provide port forwarding channels
  Author      : Jorge David de Hoz Diego
  Modification: 2024/21/10
  TODO: This is still a header file. It is required to create the CPP associated and remove the functions from here.
        To do so, it is required to define a config structure that will be defined in the header file and passed as an argument to the main task
        Only a reverse port forwarding channel is created, capable of just a single connection.
        Password-based auth is used by default.
**********************************************************************/
#include "cmxsafe.h"
#include "settings.h"


int timeout_seconds = TIMEOUT_SECONDS;
char *remote_host = SSH_REMOTE_HOST;  // Replace with your SSH server's IP or hostname
char *local_host = SSH_LOCAL_HOST;    // Replace with your SSH server's IP or hostname
int remote_port = SSH_REMOTE_PORT;    // SSH server port
char *username1 = USERNAME1;          // SSH username
char *password1 = PASSWORD1;          // SSH password (optional if using key authentication)

//CONFIGURATIONS when SSHMULTICHANNEL is enabled. Otherwise, it is ignored and takes the structure of fw_ports.h
static PortConfig portConfigsMultiChannel[] = {
  { "streamPort1", 81, 81, true, NULL },
  { "streamPort2", 80, 80, false, NULL },
  { "streamPort3", 8989, 8989, true, NULL },
  { "streamPort4", 8888, 8888, true, NULL },
};


void msg_fwd_open_channel_task(void *pvParameters) {
  char buffer[512];  
  int bytesRead = 0;
  int bytesWritten = 0;

  chan_task_param *params = (chan_task_param *)pvParameters;
  int local_port = params->local_port;
  int forward_remote_port = params->forward_remote_port;
  bool high_bw = params->high_bw;
  TaskHandle_t *handler = params->handler;


  // Accept the forwarded channel
  ssh_channel active_channel = ssh_message_channel_request_open_reply_accept(params->my_ssh_message);

  if (active_channel == NULL) {
    Serial.printf("TASK--Failed to accept forwarded channel: %s\n", ssh_get_error(*(params->my_ssh_session)));
    // Free the SSH message before exiting
    ssh_message_free(params->my_ssh_message);
    if (*handler != NULL) {
      *handler = NULL;
      vTaskDelete(NULL);
    } else return;
  }

  // Create a local client connection
  WiFiClient localClient;
  if (!localClient.connect(local_host, local_port)) {
    Serial.println("Failed to connect to local service");
    // Clean up resources
    ssh_channel_send_eof(active_channel);
    ssh_channel_close(active_channel);
    ssh_channel_free(active_channel);
    ssh_message_free(params->my_ssh_message);
    if (*handler != NULL) {
      *handler = NULL;
      vTaskDelete(NULL);
    } else return;
  }

  // Main loop to forward data
  while (true) {
    if (ssh_channel_is_open(active_channel) && !ssh_channel_is_eof(active_channel)) {
      // Read from SSH channel
      int nbytes = ssh_channel_read_nonblocking(active_channel, buffer, sizeof(buffer), 0);
      if (nbytes > 0) {
        bytesWritten = localClient.write((uint8_t *)buffer, nbytes);
        if (bytesWritten != nbytes) {
          Serial.printf("Error writing to local service: %d bytes\n", bytesWritten);
          localClient.stop();
          ssh_channel_send_eof(active_channel);
          ssh_channel_close(active_channel);
          ssh_channel_free(active_channel);
          ssh_message_free(params->my_ssh_message);
          if (*handler != NULL) {
            *handler = NULL;
            vTaskDelete(NULL);
          } else return;
        }
      }
    }

    // Read from local client and forward to SSH channel
    if (localClient.connected()) {
      bytesRead = localClient.readBytes(buffer, sizeof(buffer));
      if (bytesRead > 0) {
        bytesWritten = ssh_channel_write(active_channel, buffer, bytesRead);
        if (bytesWritten != bytesRead) {
          Serial.printf("Error writing to SSH channel: %d bytes\n", bytesWritten);
          localClient.stop();
          //ssh_channel_close(active_channel);
          ssh_channel_free(active_channel);
          ssh_message_free(params->my_ssh_message);
          if (*handler != NULL) {
            *handler = NULL;
            vTaskDelete(NULL);
          } else return;
        }
      }
    }

    //Delay to allow task switching
    //vTaskDelay(1 / portTICK_PERIOD_MS);
    // Check for closed connections
    if (!localClient.connected() || ssh_channel_is_closed(active_channel) || ssh_channel_is_eof(active_channel)) {
      Serial.println("Connection closed, cleaning up...");

      // Clean up resources
      Serial.println("Local client stop...");
      localClient.stop();

      //Serial.println("send ssh eof...");
      //ssh_channel_send_eof(active_channel);

      //Serial.println("close active channel...");
      //ssh_channel_close(active_channel);

      //Serial.println("free ssh message...");
      //if (params->my_ssh_message){
      //    ssh_message_free(params->my_ssh_message);
      //}

      Serial.println("free ssh channel...");
      ssh_channel_free(active_channel);

      // Delete task
      if (*handler != NULL) {
        *handler = NULL;
        vTaskDelete(NULL);
      } else return;
    }
  }
}


void ssh_port_forwarding_task(void *pvParameters) {
  TaskParameters *parameters = (TaskParameters *)pvParameters;
  ssh_session my_ssh_session = NULL;
  ssh_message message = NULL;
  TaskHandle_t msg_fwd_open_channel_task1 = NULL;
  chan_task_param TaskParameters1;
  int dest_port = NULL;
  int proxy_match = NULL;
#define MAX_MESSAGES 10
  ssh_message messageArray[MAX_MESSAGES] = { NULL };  // Initialize array
  int currentMessageIndex = 0;

  int local_port = parameters->local_port;
  int forward_remote_port = parameters->forward_remote_port;
  int high_bw = parameters->high_bw;
  bool multichannel = SSHMULTICHANNEL;
  int num_proxies = 0;
  PortConfig* portConfigs = NULL;
  PortConfig portConfigsSingleChannel[1] = {{ "streamPort1", local_port, forward_remote_port, high_bw, NULL }};

  if (!multichannel) {
       portConfigs = portConfigsSingleChannel;
       num_proxies = 1;
  }else{
       portConfigs = portConfigsMultiChannel;
       num_proxies = sizeof(portConfigsMultiChannel) / sizeof(portConfigsMultiChannel[0]);
  }

  while (1) {
    // Initialize SSH session
    ssh_init();
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL) {
      Serial.println("Failed to create SSH session");
      vTaskDelay(10000 / portTICK_PERIOD_MS);  // Retry after delay
      continue;
    }

int sock_fd = ssh_get_fd(my_ssh_session);
int buffer_size = 1024; // Limit TCP buffer size to 4 KB

setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));

    // Set SSH options
    int verbosity = SSH_LOG_NOLOG;
    int timeout = 60000;
    int keepalive = 30000;
    bool compression = 0;
    bool nodelay = 1;
    ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_TIMEOUT, &timeout);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, remote_host);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &remote_port);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, username1);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_CIPHERS_C_S, "aes256-gcm@openssh.com");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_CIPHERS_S_C, "aes256-gcm@openssh.com,");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_KEY_EXCHANGE, "curve25519-sha256");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOSTKEYS, "ecdsa-sha2-nistp256");  //NOT VERIFYING HOST KEYS OR CERTIFICATES. not necessary
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HMAC_S_C, "hmac-sha2-512");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HMAC_C_S, "hmac-sha2-512");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_NODELAY, &nodelay);
    // Connect to the SSH server
    if (ssh_connect(my_ssh_session) != SSH_OK) {
      Serial.printf("Error connecting to SSH server: %s\n", ssh_get_error(my_ssh_session));
      ssh_free(my_ssh_session);
      my_ssh_session = NULL;
      vTaskDelay(10000 / portTICK_PERIOD_MS);
      continue;
    }

    // Authenticate
    if (ssh_userauth_password(my_ssh_session, NULL, password1) != SSH_AUTH_SUCCESS) {
      Serial.printf("SSH authentication failed: %s\n", ssh_get_error(my_ssh_session));
      ssh_disconnect(my_ssh_session);
      ssh_free(my_ssh_session);
      my_ssh_session = NULL;
      vTaskDelay(10000 / portTICK_PERIOD_MS);
      continue;
    }

    Serial.println("SSH client authenticated successfully");

    // Set up port forwarding portConfigs[i].forward_remote_port, portConfigs[i].local_port
    for (size_t i = 0; i < num_proxies; i++) {
      Serial.printf("Setting up reverse proxy %zu: Remote Port = %d, Local Port = %d\n", i, portConfigs[i].forward_remote_port, portConfigs[i].local_port);
      // We have set the binding remote address to null. Default SSH SERVER implementations would try to bind to all addresses, but the CMXsafe implementation binds
      //This is only for a specific local address assigned to this device [#MAC_DEVICE#MAC_CMXGW] to generate the corresponding identity socket.
      //In CMXsafe, the proxied socket matches the original socket (no difference), which means that in fw_ports, both ports would be the same. This is to facilitate
      //compatibility in applications. For instance, VideoWebServer uses 80 port for the site and 81 port for the streaming. Any mapping would avoid a straightforward operation.
      if (ssh_channel_listen_forward(my_ssh_session, NULL, portConfigs[i].forward_remote_port, NULL) != SSH_OK) {
        Serial.printf("Failed to set up port forwarding: %s\n", ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        my_ssh_session = NULL;
        vTaskDelay(10000 / portTICK_PERIOD_MS);
        continue;
        //TODO: ALWAYS ALLOW AT LEAST A PORT-FORWARDING, THE ONE FOR REMOTE MANAGEMENT
      }
    }

    // Main loop to handle messages
    while (ssh_is_connected(my_ssh_session)) {
      message = ssh_message_get(my_ssh_session);  // Blocking
      if (message) {
        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN) {


          //Validate working connections: only one per proxy. To create the new task, the requested connection must correspond to a proxy without a connection.
          /*
                    for (size_t i = 0; i < num_proxies; i++) {
                        if (&(portConfigs[i].handler) != NULL && eTaskGetState(&(portConfigs[i].handler) != eDeleted) {
                            Serial.println("already exists another connection or current connection."); 
                            continue;
                        }
                    }
                    */

          //We look for the correct local port through the mappings available using the remote forwarded port as key
          dest_port = ssh_message_channel_request_open_destination_port(message);
          local_port = NULL;
          for (size_t i = 0; i < num_proxies; i++) {
            if (portConfigs[i].forward_remote_port == dest_port) {
              Serial.printf("Handling reverse proxy for remote port: %d -> LOCAL %d\n", portConfigs[i].forward_remote_port, portConfigs[i].local_port);
              local_port = portConfigs[i].local_port;
              if (portConfigs[i].handler != NULL && eTaskGetState(portConfigs[i].handler) != eDeleted) {
                local_port = NULL;  //Already a connection ongoing. only one per proxy
                Serial.printf("Not allowed. Already a connection ongoing: %d -> LOCAL %d\n", portConfigs[i].forward_remote_port, portConfigs[i].local_port);
              }
              proxy_match = i;

              break;
            }
          }

          if (local_port != NULL) {
            // Set up parameters for the new task
            TaskParameters1.my_ssh_session = &my_ssh_session;
            TaskParameters1.my_ssh_message = message;
            TaskParameters1.local_port = local_port;
            TaskParameters1.forward_remote_port = dest_port;
            TaskParameters1.high_bw = portConfigs[proxy_match].high_bw;
            TaskParameters1.handler = &(portConfigs[proxy_match].handler);

            //HOW TO HANDLE INCOMING CONNECTIONS it works both ways:
            // 1) With sub-tasks. Problem: libssh is not optimized and seems unstable. It should be tested in updated environments and disabled encryption hardware support
            // 2) A single task and multiple sessions: more stable and reliable, but consumes more RAM

            // TODO: multiple channels in a single task. Probably more stable than with subtasks:
            //1 All reverse socket proxies are initialised above. An array of messages is prepared
            //2 It is assumed that there is just one possible connection incoming from each reverse port forwarded channel
            //3 A status of each potential incoming connection and local forwarding is set in a special control structure
            //4 A general loop verifies the status of connections, accepts or rejects incoming connections, updates the control struct, and sends/receives sequentially the sent/received bytes
            //


            if (multichannel) {
              //INSTEAD OF A TASK, A FUNCTION THAT HAS AN ARRAY OF COMPONENTS TO CHECK CONNECTIONS/ OPEN LOCAL CONNECTIONS/CLOSE LOCAL CONNECTIONS
              xTaskCreatePinnedToCore(msg_fwd_open_channel_task, portConfigs[proxy_match].name, 8192, &TaskParameters1, 21, &(portConfigs[proxy_match].handler), 1);
            } else {
              msg_fwd_open_channel_task(&TaskParameters1);
            }
          }

        } else {
          if (message) {
            ssh_message_free(message);
            message = NULL;
          }
        }
      }
      vTaskDelay(500 / portTICK_PERIOD_MS);  // Prevent tight loop
    }

    // Cleanup resources
    Serial.println("SSH session disconnected, cleaning up resources...");
    if (msg_fwd_open_channel_task1 != NULL && eTaskGetState(msg_fwd_open_channel_task1) != eDeleted) {
      Serial.println("Deleting msg_fwd_open_channel_task1");
      vTaskDelete(msg_fwd_open_channel_task1);
    }
    if (message) {
      ssh_message_free(message);
      message = NULL;
    }
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);  //Freeing SSH session appears to clear all SSH channels as well
    my_ssh_session = NULL;

    vTaskDelay(((rand() % 8) + 3) / portTICK_PERIOD_MS);  // Retry after delay
  }

  // Final cleanup before task deletion
  if (my_ssh_session) {
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
  }
  if (message) {
    ssh_message_free(message);
    message = NULL;
  }
  vTaskDelete(NULL);  //usually this happens when the connection stops remotely
}
