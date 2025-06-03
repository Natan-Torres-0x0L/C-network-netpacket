#define _GNU_SOURCE // Using GNU source implementation for SO_BINDTODEVICE

#include "netpacket.h"

#include <network/sockets/sockets.h>

#include <netpacket/packet.h>
#include <netinet/if_ether.h>

#include <net/ethernet.h>
#include <net/if.h>

// #include <linux/if_packet.h>
// #include <linux/if_ether.h>
//
// #include <linux/ethernet.h>
// #include <linux/if.h>

#include <strings/strings.h>
#include <string.h>

#include <stdarg.h>
#include <stdlib.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


#define NETPACKET_LAYER3_IPV4_SIZE 20
#define NETPACKET_LAYER3_IPV6_SIZE 40


struct netpacket_live {
  struct sockaddr_ll linklayer_addr;
  socket_t layer2_socket, layer3_socket;

  int write_buffer_length;
  int read_buffer_length;

  netpacket_protocol_t protocol;
  netpacket_layer_t layer;

  bool promiscuos;
};


static inline int
netpacket_live_layer2_bind(netpacket_live_t *live, struct netlink_interface *iface) {
  if (socket_setoption(live->layer2_socket, SOL_PACKET, SO_SNDBUF, &live->write_buffer_length, sizeof(live->write_buffer_length)) == -1)
    return -1;

  if (socket_setoption(live->layer2_socket, SOL_PACKET, SO_RCVBUF, &live->read_buffer_length, sizeof(live->read_buffer_length)) == -1)
    return -1;

  memcpy(&live->linklayer_addr.sll_addr, &iface->mac, MACIEEE802_SIZE);
  live->linklayer_addr.sll_ifindex  = (int)iface->index;
  live->linklayer_addr.sll_family   = AF_PACKET;
  live->linklayer_addr.sll_protocol = htons(ETH_P_ALL);
  live->linklayer_addr.sll_halen    = MACIEEE802_SIZE;

  return socket_bind(live->layer2_socket, (struct sockaddr *)&live->linklayer_addr, sizeof(live->linklayer_addr));
}

static inline int
netpacket_live_layer3_bind(netpacket_live_t *live, struct netlink_interface *iface) {
  int broadcast = 1, hdrincl = 1, protocol = ((live->protocol == NETPACKET_PROTOCOL_IPV6) ? IPPROTO_IPV6 : IPPROTO_IP);

  if (live->protocol == NETPACKET_PROTOCOL_IPV4 && socket_setoption(live->layer3_socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) == -1)
    return -1;

  if (socket_setoption(live->layer3_socket, protocol, SO_SNDBUF, &live->write_buffer_length, sizeof(live->write_buffer_length)) == -1)
    return -1;

  if (socket_setoption(live->layer3_socket, protocol, SO_RCVBUF, &live->read_buffer_length, sizeof(live->read_buffer_length)) == -1)
    return -1;

  if (socket_setoption(live->layer3_socket, protocol, IP_HDRINCL, &hdrincl, sizeof(hdrincl)) == -1)
    return -1;

#ifdef SO_BINDTODEVICE
  if (socket_setoption(live->layer3_socket, SOL_SOCKET, SO_BINDTODEVICE, iface->name, (socklen_t)string_length(iface->name)) == -1)
    return -1;
#endif

  return 1;
}

static int
netpacket_live_layer_new(netpacket_live_t *live, netpacket_layer_t layer, va_list args) { 
  switch (layer) {
    case NETPACKET_LAYER2: {
      if ((live->layer2_socket = socket_new(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == SOCKET_INVALID)
        return -1;

      live->layer3_socket = SOCKET_INVALID;

      return 1;
    }

    case NETPACKET_LAYER3: {
      int family = ((live->protocol = (netpacket_protocol_t)va_arg(args, int)) == NETPACKET_PROTOCOL_IPV6 ? AF_INET6 : AF_INET);
      int protocol = ((family == AF_INET6) ? htons(ETH_P_IPV6) : htons(ETH_P_IP));

      if ((live->layer2_socket = socket_new(AF_PACKET, SOCK_DGRAM, protocol)) == SOCKET_INVALID)
        return -1;
      if ((live->layer3_socket = socket_new(family, SOCK_RAW, IPPROTO_RAW)) == SOCKET_INVALID)
        return -1;

      return 1;
    }
  }

  return -1;
}

static inline int
netpacket_live_setpromiscuos(netpacket_live_t *live, struct netlink_interface *iface) {
  struct packet_mreq packet_mreq = { .mr_ifindex = (int)iface->index, .mr_type = PACKET_MR_PROMISC };

  if (socket_setoption(live->layer2_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &packet_mreq, sizeof(packet_mreq)) < 0)
    return -1;

  return 1;
}

netpacket_live_t *
netpacket_live_bind(struct netlink_interface *iface, netpacket_layer_t layer, netpacket_mode_t mode, ...) {
  netpacket_live_t *live = NULL;
  va_list args;

  va_start(args, mode);

  if (!(live = (netpacket_live_t *)calloc(1, sizeof(netpacket_live_t)))) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }

  live->write_buffer_length = 65535;
  live->read_buffer_length = 65535;

  if (netpacket_live_layer_new(live, (live->layer = layer), args) == -1) {
    netpacket_seterror(NETPACKET_ESOCKET);
    goto _return;
  }
  if (live->layer == NETPACKET_LAYER3 && netpacket_live_layer3_bind(live, iface) == -1) {
    netpacket_seterror(NETPACKET_ESOCKET);
    goto _return;
  }
  if (netpacket_live_layer2_bind(live, iface) == -1) {
    netpacket_seterror(NETPACKET_ESOCKET);
    goto _return;
  }

  live->promiscuos = (mode == NETPACKET_PROMISCUOS);

  if (live->promiscuos && netpacket_live_setpromiscuos(live, iface) == -1) {
    netpacket_seterror(NETPACKET_ESOCKET);
    goto _return;
  }

  va_end(args);

  return live;

_return:
  netpacket_live_close(live);
  va_end(args);

  return NULL;
}

ssize_t
netpacket_live_recv(netpacket_live_t *live, void *buffer, size_t length, struct netpacket_timeout *timeout) {
  ssize_t received = -1;

  if ((received = socket_recvfrom(live->layer2_socket, buffer, length, 0, NULL, NULL, (struct socket_timeout *)timeout)) == -1) {
    netpacket_seterror(NETPACKET_ESOCKET);
    return -1;
  }

  if (timeout && received == 0) {
    netpacket_seterror(NETPACKET_ETIMEOUT);
    return 0;
  }

  return received;
}

static inline void
netpacket_live_layer3_network_sockaddr_in(const void *buffer, struct sockaddr *network_addr, socklen_t *network_addr_size) {
  memcpy(&((struct sockaddr_in *)network_addr)->sin_addr, &((const uint8_t *)buffer)[16], INETV4_SIZE);
  network_addr->sa_family = AF_INET;
  *network_addr_size = sizeof(struct sockaddr_in);
}

static inline void
netpacket_live_layer3_network_sockaddr_in6(const void *buffer, struct sockaddr *network_addr, socklen_t *network_addr_size) {
  memcpy(&((struct sockaddr_in6 *)network_addr)->sin6_addr, &((const uint8_t *)buffer)[24], INETV6_SIZE);
  network_addr->sa_family = AF_INET6;
  *network_addr_size = sizeof(struct sockaddr_in6);
}

static inline int
netpacket_live_layer3_network_sockaddr(netpacket_live_t *live, const void *buffer, size_t length, struct sockaddr *network_addr, socklen_t *network_addr_size) {
  uint8_t protocol = ((((const uint8_t *)buffer)[0] >> 4) & 0x0F);

  if ((protocol == NETPACKET_PROTOCOL_IPV4 && length < NETPACKET_LAYER3_IPV4_SIZE) || (protocol == NETPACKET_PROTOCOL_IPV6 && length < NETPACKET_LAYER3_IPV6_SIZE))
    return -1;
  if (live->protocol != protocol) 
    return -1;

  if (protocol == NETPACKET_PROTOCOL_IPV4)
    netpacket_live_layer3_network_sockaddr_in(buffer, network_addr, network_addr_size);

  if (protocol == NETPACKET_PROTOCOL_IPV6)
    netpacket_live_layer3_network_sockaddr_in6(buffer, network_addr, network_addr_size);

  return 1;
}

ssize_t
netpacket_live_sendto(netpacket_live_t *live, const void *buffer, size_t length) {
  socket_t socket = ((live->layer == NETPACKET_LAYER3) ? live->layer3_socket : live->layer2_socket);

  struct sockaddr_storage network_addr = {0};
  socklen_t network_addr_size = 0;

  ssize_t sent = -1;

  if (netpacket_live_layer3_network_sockaddr(live, buffer, length, (struct sockaddr *)&network_addr, &network_addr_size) == -1) {
    netpacket_seterror(NETPACKET_EPROTOCOL);
    return -1;
  }

  if ((sent = socket_sendto(socket, buffer, length, 0, (struct sockaddr *)&network_addr, network_addr_size)) == -1) {
    netpacket_seterror(NETPACKET_ESOCKET);
    return -1;
  }

  return sent;
}

/*
ssize_t
netpacket_live_sendto(netpacket_live_t *live, const void *buffer, size_t length, struct sockaddr *network_addr, socklen_t network_addr_size) {
  socket_t layer = ((live->layer == NETPACKET_LAYER3) ? live->layer3_socket : live->layer2_socket);
  ssize_t sent = -1;

  if ((sent = socket_sendto(layer, buffer, length, 0, network_addr, network_addr_size)) == -1) {
    netpacket_seterror(NETPACKET_ESOCKET);
    return -1;
  }

  return sent;
}
*/

ssize_t
netpacket_live_send(netpacket_live_t *live, const void *buffer, size_t length) {
  ssize_t sent = -1;

  if ((sent = socket_sendto(live->layer2_socket, buffer, length, 0, (struct sockaddr *)&live->linklayer_addr, sizeof(live->linklayer_addr))) == -1) {
    netpacket_seterror(NETPACKET_ESOCKET);
    return -1;
  }

  return sent;
}

void
netpacket_live_close(netpacket_live_t *live) {
  if (live) {
    if (live->layer2_socket != SOCKET_INVALID)
      socket_close(live->layer2_socket), live->layer2_socket = SOCKET_INVALID;
    if (live->layer3_socket != SOCKET_INVALID)
      socket_close(live->layer3_socket), live->layer3_socket = SOCKET_INVALID;

    free(live);
  }
}
