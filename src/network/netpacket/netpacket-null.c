#include "netpacket.h"


struct netpacket_live {
};


netpacket_live_t *
netpacket_live_bind(struct netlink_interface *iface, netpacket_layer_t layer, netpacket_mode_t mode) {
  netpacket_seterror(NETPACKET_ENOSUPPORT);
  return NULL;
}

ssize_t
netpacket_live_recv(netpacket_live_t *live, void *buffer, size_t length, struct netpacket_timeout *timeout) {
  netpacket_seterror(NETPACKET_ENOSUPPORT);
  return -1;
}

ssize_t
netpacket_live_send(netpacket_live_t *live, const void *buffer, size_t length) {
  netpacket_seterror(NETPACKET_ENOSUPPORT);
  return -1;
}

void
netpacket_live_close(netpacket_live_t *) {
  netpacket_seterror(NETPACKET_ENOSUPPORT);
}
