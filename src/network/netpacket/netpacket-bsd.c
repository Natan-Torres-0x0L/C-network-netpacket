#include "netpacket.h"

#include <network/sockets/sockets.h>

#include <net/bpf.h>
#include <net/if.h>

#include <sys/types.h>
#include <sys/ioctl.h>

#include <unistd.h>
#include <fcntl.h>

#include <string.h>

#include <stdlib.h>
#include <stdio.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NETPACKET_ETHERNET_PROTOCOL_IPV4     0x0800
#define NETPACKET_ETHERNET_PROTOCOL_IPV6     0x86DD

#define NETPACKET_ETHERNET_SIZE              14

#define NETPACKET_BPF_DEVICE_LAST_IDENTIFIER 99
#define NETPACKET_BPF_DEVICE_NAME_LENGTH     sizeof("/dev/bpf00")

#define NETPACKET_BPF_DEVICE_INVALID         -1


struct netpacket_live {
  char bpf_device_name[NETPACKET_BPF_DEVICE_NAME_LENGTH];
  int bpf_device;

  int read_buffer_length;
  uint8_t *read_buffer;

  netpacket_layer_t layer;
  bool promiscuos, loopback;
};


static inline int
netpacket_live_bpf_device_open(netpacket_live_t *live) {
  int bpf_device = NETPACKET_BPF_DEVICE_INVALID;
  uint8_t id;

  for (id = 0; id < NETPACKET_BPF_DEVICE_LAST_IDENTIFIER; id++) {
    snprintf(live->bpf_device_name, sizeof(live->bpf_device_name), "/dev/bpf%d", id);

    if ((bpf_device = open(live->bpf_device_name, O_RDWR)) != -1)
      break;
  }

  return bpf_device;
}

static int
netpacket_live_bpf_device_setif(netpacket_live_t *live, struct netlink_interface *iface) {
  int immediate = 1, buffer_length = 0;
  struct ifreq ifreq = {0};

  strncpy(ifreq.ifr_name, iface->name, sizeof(ifreq.ifr_name));

  if (ioctl(live->bpf_device, BIOCSETIF, &ifreq) == -1)
    return -1;

  if (ioctl(live->bpf_device, BIOCIMMEDIATE, &immediate) == -1)
    return -1;

  if (ioctl(live->bpf_device, BIOCGBLEN, &buffer_length) == -1)
    return -1;
  live->read_buffer_length = buffer_length;

  if (!(live->read_buffer = (uint8_t *)calloc(1, (size_t)live->read_buffer_length+sizeof(struct bpf_hdr))))
    return -1;

  return 1;
}

static inline int
netpacket_live_setpromiscuos(netpacket_live_t *live) {
  if (ioctl(live->bpf_device, BIOCPROMISC, NULL) == -1)
    return -1;

  return 1;
}

netpacket_live_t *
netpacket_live_bind(struct netlink_interface *iface, netpacket_layer_t layer, netpacket_mode_t mode, ...) {
  netpacket_live_t *live = NULL;

  if (!(live = (netpacket_live_t *)calloc(1, sizeof(netpacket_live_t)))) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }

  if ((live->bpf_device = netpacket_live_bpf_device_open(live)) == -1) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }
  if (netpacket_live_bpf_device_setif(live, iface) == -1) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }

  live->promiscuos = (mode == NETPACKET_PROMISCUOS);

  if (live->promiscuos && netpacket_live_setpromiscuos(live) == -1) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }

  live->loopback = (iface->flags & NETLINK_IFLOOPBACK);

  return live;

_return:
  netpacket_live_close(live);
  return NULL;
}

static inline void
netpacket_live_layer2_loopback_complement(struct bpf_hdr *bpfh, size_t received, void *buffer, size_t length) {
  size_t buffer_offset = ((length < NETPACKET_ETHERNET_SIZE) ? length : NETPACKET_ETHERNET_SIZE);
  size_t bpfh_offset = sizeof(int);

  int family = *(int *)&((uint8_t *)bpfh+bpfh->bh_hdrlen)[0];

  family = ((family == AF_INET) ? htons(NETPACKET_ETHERNET_PROTOCOL_IPV4) : htons(NETPACKET_ETHERNET_PROTOCOL_IPV6));

  memcpy(buffer+NETPACKET_ETHERNET_SIZE-sizeof(uint16_t), &family, sizeof(uint16_t));
  memcpy(buffer+buffer_offset, (uint8_t *)bpfh+bpfh->bh_hdrlen+bpfh_offset, (size_t)received-bpfh_offset);
}

ssize_t
netpacket_live_recv(netpacket_live_t *live, void *buffer, size_t length, struct netpacket_timeout *timeout) {
  struct timeval timeval = { .tv_sec = ((timeout) ? timeout->sec+(timeout->usec/1000) : 0), };
  struct timeval *timevalptr = ((timeout) ? &timeval : NULL);

  struct bpf_hdr *bpfh = NULL;

  ssize_t received = -1;

  if (ioctl(live->bpf_device, BIOCSRTIMEOUT, timevalptr) < 0) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }

  if ((received = (ssize_t)read(live->bpf_device, live->read_buffer, (size_t)live->read_buffer_length)) < 0) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }

  if (received == 0) {
    netpacket_seterror(NETPACKET_ETIMEOUT);
    return 0;
  }

  bpfh = (struct bpf_hdr *)live->read_buffer;

  if ((received = (ssize_t)bpfh->bh_caplen) > (ssize_t)length)
    received = (ssize_t)length;

  if (live->loopback) {
    netpacket_live_layer2_loopback_complement(bpfh, received, buffer, length);
    return received;
  }

  memcpy(buffer, (uint8_t *)bpfh+bpfh->bh_hdrlen, (size_t)received);

_return:
  return received;
}

ssize_t
netpacket_live_send(netpacket_live_t *live, const void *buffer, size_t length) {
  ssize_t sent = -1;

  if ((sent = (ssize_t)write(live->bpf_device, buffer, length)) < 0) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    return -1;
  }

  return sent;
}

void
netpacket_live_close(netpacket_live_t *live) {
  if (live) {
    if (live->bpf_device != NETPACKET_BPF_DEVICE_INVALID)
      close(live->bpf_device), live->bpf_device = NETPACKET_BPF_DEVICE_INVALID;

    if (live->read_buffer)
      free(live->read_buffer), live->read_buffer = NULL;

    free(live);
  }
}
