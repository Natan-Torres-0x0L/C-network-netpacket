#ifndef _NETWORK_NETPACKET_NETPACKET_LINUX_H
#define _NETWORK_NETPACKET_NETPACKET_LINUX_H

#ifdef __cplusplus
extern "C" {
#endif

// #include <network/sockets/sockets.h>

#include <sys/types.h>


typedef enum {
  NETPACKET_PROTOCOL_IPV4 = 0x04, NETPACKET_PROTOCOL_IPV6 = 0x06
} netpacket_protocol_t;

// typedef signed long long int ssize_t; // #define ssize_t signed long long int
// typedef unsigned long long int size_t; //  #define size_t  unsigned long long int

typedef struct netpacket_live netpacket_live_t;


// extern ssize_t netpacket_live_sendto(netpacket_live_t *, const void *, size_t, struct sockaddr *, socklen_t);
extern ssize_t netpacket_live_sendto(netpacket_live_t *, const void *, size_t);

// extern socketfd_t netpacket_live_socketfd(netpacket_live_t *);

#ifdef __cplusplus
}
#endif

#endif
