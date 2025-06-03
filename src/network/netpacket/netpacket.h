#ifndef _NETWORK_NETPACKET_NETPACKET_H
#define _NETWORK_NETPACKET_NETPACKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <network/netlink/netlink.h>

#if defined _WIN16 || defined _WIN32 || defined _WIN64 || defined __WIN32__ || defined __TOS_WIN__ || defined __WINDOWS__
  #include "netpacket-windows.h"

#elif defined __linux__ || defined __linux
  #include "netpacket-linux.h"

#elif defined __APPLE__ && defined __MACH__
  #include "netpacket-darwin.h"

#elif defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__ || defined __bsdi__ || defined __DragonFly__ || defined _SYSTYPE_BSD
  #include "netpacket-bsd.h"

#else
  #include "netpacket-null.h"

#endif

#include "netpacket-errors.h"

#include <sys/types.h>
#include <stddef.h>


typedef enum {
  NETPACKET_NORMAL = 0x0000, NETPACKET_PROMISCUOS = 0x0001,
} netpacket_mode_t;

typedef enum {
  NETPACKET_LAYER2 = 0x0002, NETPACKET_LAYER3 = 0x0003,
} netpacket_layer_t;

struct netpacket_timeout {
  long sec, usec;
};


extern netpacket_live_t *netpacket_live_bind(struct netlink_interface *, netpacket_layer_t, netpacket_mode_t, ...);

extern ssize_t netpacket_live_recv(netpacket_live_t *, void *, size_t, struct netpacket_timeout *);
extern ssize_t netpacket_live_send(netpacket_live_t *, const void *, size_t);

extern void netpacket_live_close(netpacket_live_t *);

#ifdef __cplusplus
}
#endif

#endif
