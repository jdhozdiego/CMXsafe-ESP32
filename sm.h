#include <WiFiClient.h>
#include <lwip/sockets.h>
#include <lwip/netif.h>
#include <lwip/ip.h>
#include <lwip/tcp.h>
#include <lwip/inet.h>
#include <esp_system.h>
#include "settings.h"

void setup_sm();
// Convert IPAddress type to uint32_t (raw format)

err_t firewall_ip_input(struct pbuf* p, struct netif* inp);


