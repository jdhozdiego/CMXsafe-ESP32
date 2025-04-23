#include "sm.h"
#include <WiFiClient.h>



err_t (*original_ip_input)(struct pbuf* p, struct netif* inp);

bool stringToIPAddress(const char* ipString, IPAddress& ipAddress) {
    uint8_t octets[4] = {0};
    int octetIndex = 0;
    const char* ptr = ipString;

    // Parse each octet
    while (*ptr) {
        if (*ptr >= '0' && *ptr <= '9') {
            octets[octetIndex] = octets[octetIndex] * 10 + (*ptr - '0');
            if (octets[octetIndex] > 255) {
                return false; // Invalid IP address
            }
        } else if (*ptr == '.') {
            if (++octetIndex > 3) {
                return false; // Too many octets
            }
        } else {
            return false; // Invalid character
        }
        ptr++;
    }

    if (octetIndex != 3) {
        return false; // Not enough octets
    }

    // Assign the parsed octets to the IPAddress object
    ipAddress = IPAddress(octets[0], octets[1], octets[2], octets[3]);
    return true;
}
int allowed_port = SSH_REMOTE_PORT;  // SSH server port
IPAddress allowed_ip;
bool result=stringToIPAddress(SSH_REMOTE_HOST, allowed_ip);

uint32_t ipToRaw(const IPAddress& ip) {
  return (ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3];
}
err_t firewall_ip_input(struct pbuf* p, struct netif* inp) {

  //IPAddress allowed_ip;
  //convertStringToIP(allow_ip, allowed_ip);
  //uint16_t allowed_port = allow_port;
  // Ensure the packet is large enough to contain an Ethernet frame and IP header
  if (p->len < 14 + IP_HLEN) {
    // Not enough length, process packet normally
    return original_ip_input(p, inp);
  }

  
  
  // Ensure the packet is large enough to contain an Ethernet frame
  if (p->len < 14 ) {
    // Not enough length, discard
    pbuf_free(p);
    return ERR_OK;
  }


  // Parse the Ethernet header
  uint8_t* eth_frame = (uint8_t*)p->payload;
  uint16_t eth_type = (eth_frame[12] << 8) | eth_frame[13];

  // Check if it's an ARP packet (EtherType 0x0806)
  if (eth_type == 0x0806 ) {
    //ARP is processed as usual
    return original_ip_input(p, inp); 
  }

  // Check if it's an IPv4 (EtherType 0x0800)
  if (eth_type != 0x0800 ) {
    // Not an IPv4 packet, Discard
    pbuf_free(p);
    return ERR_OK;
  }



  // Get a pointer to the IP header
  struct ip_hdr* iphdr = (struct ip_hdr*)(p->payload + 14);

  // Check if it's IPv4
  if (IPH_V(iphdr) != 4) {
    // Not an IPv4 packet, discard
    pbuf_free(p);
    return ERR_OK;
  }

  // Extract and convert the IPs to host byte order
  uint32_t src_ip_raw = ntohl(iphdr->src.addr);
  uint32_t dest_ip_raw = ntohl(iphdr->dest.addr);

  // Convert the allowed IP to raw format
  uint32_t allowed_ip_raw = ipToRaw(allowed_ip);

  // Ensure the packet has enough space for the TCP/UDP header
  uint16_t ip_header_length = IPH_HL(iphdr) * 4;
  if (p->len < 14 + ip_header_length + 8) {
    // Not enough length for transport layer header, discard
    pbuf_free(p);
    return ERR_OK;
  }

  // Determine if the packet is TCP or UDP
  uint8_t protocol = IPH_PROTO(iphdr);
  if (protocol != IP_PROTO_TCP && protocol != IP_PROTO_UDP) {
    // Not TCP or UDP, process packet normally
    // return original_ip_input(p, inp);
    pbuf_free(p);
    return ERR_OK;
  }

  // Get a pointer to the transport header (TCP/UDP)
  uint8_t* transport_header = (uint8_t*)p->payload + 14 + ip_header_length;
  uint16_t src_port = (transport_header[0] << 8) | transport_header[1];
  uint16_t dest_port = (transport_header[2] << 8) | transport_header[3];

  // Allow packet if source or destination matches allowed IP and port
  if ((src_ip_raw == allowed_ip_raw && src_port == allowed_port) ||
      (dest_ip_raw == allowed_ip_raw && dest_port == allowed_port)) {
    return original_ip_input(p, inp);  // Pass packet through
  }

  // Block the packet by freeing the buffer
  pbuf_free(p);
  return ERR_OK;  // Return OK to indicate packet is handled
}

void setup_sm(){

  // Hook the IP input function to insert our firewall
  struct netif* netif = netif_list;  // Get the default network interface
  original_ip_input = netif->input;  // Save the original IP input handler
  netif->input = firewall_ip_input;  // Replace it with our firewall function
    // Set global lwIP parameters

}