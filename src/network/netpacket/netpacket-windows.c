#include "netpacket.h"

#include <Packet32.h>
#include <windows.h>
#include <basetsd.h>

#include <string.h>

#include <stdlib.h>
#include <stdio.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NETPACKET_NDIS_PACKET_TYPE_PROMISCUOUS 0x00000020
#define NETPACKET_NDIS_PACKET_TYPE_ALL_LOCAL   0x00000080

#define NETPACKET_ADAPTER_DEVICE_NAME_LENGTH   ADAPTER_NAME_LENGTH

struct netpacket_live {
  char adapter_device[NETPACKET_ADAPTER_DEVICE_NAME_LENGTH];
  LPADAPTER adapter;

  size_t write_buffer_length;
  uint8_t *write_buffer;

  LPPACKET write_packet;

  size_t read_buffer_length;
  uint8_t *read_buffer;

  LPPACKET read_packet;

  netpacket_layer_t layer;
  bool promiscuos;
};


static inline int
netpacket_live_setpromiscuos(netpacket_live_t *live) {
  if (!PacketSetHwFilter(live->adapter, NETPACKET_NDIS_PACKET_TYPE_PROMISCUOUS))
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

  snprintf(live->adapter_device, sizeof(live->adapter_device), "\\Device\\NPF_%s", iface->adapter_name);

  if (!(live->adapter = PacketOpenAdapter(live->adapter_device))) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }

  live->write_buffer_length = 4096;
  if (!(live->write_buffer = (uint8_t *)calloc(live->write_buffer_length, sizeof(uint8_t)))) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }
  if (!(live->write_packet = PacketAllocatePacket())) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }

  PacketInitPacket(live->write_packet, live->write_buffer, (UINT)live->write_buffer_length);

  live->read_buffer_length = 4096;
  if (!(live->read_buffer = (uint8_t *)calloc(live->read_buffer_length, sizeof(uint8_t)))) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }
  if (!(live->read_packet = PacketAllocatePacket())) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }

  PacketInitPacket(live->read_packet, live->read_buffer, (UINT)live->read_buffer_length);

  if (!PacketSetMode(live->adapter, PACKET_MODE_CAPT)) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }
  if (!PacketSetHwFilter(live->adapter, NETPACKET_NDIS_PACKET_TYPE_ALL_LOCAL)) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }

  live->promiscuos = (mode == NETPACKET_PROMISCUOS);

  if (live->promiscuos && netpacket_live_setpromiscuos(live) == -1) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }

  if (!PacketSetBuff(live->adapter, 65535)) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }

  if (!PacketSetMinToCopy(live->adapter, 1)) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }

  return live;

_return:
  netpacket_live_close(live);
  return NULL;
}

ssize_t
netpacket_live_recv(netpacket_live_t *live, void *buffer, size_t length, struct netpacket_timeout *timeout) {
  int timeval = ((timeout) ? ((timeout->sec*1000)+(timeout->usec/1000)) : (int)INFINITE);
  struct bpf_hdr *bpfh = NULL;

  ssize_t received = -1;

  if (!PacketSetReadTimeout(live->adapter, timeval)) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    return -1;
  }

  memset(live->read_packet->Buffer, 0, live->read_packet->Length);

  if (!PacketReceivePacket(live->adapter, live->read_packet, false)) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    return -1;
  }

  bpfh = (struct bpf_hdr *)live->read_packet->Buffer;

  if ((received = (ssize_t)bpfh->bh_caplen) > (ssize_t)length)
    received = (ssize_t)length;

  if (timeout && received == -1) {
    netpacket_seterror(NETPACKET_ETIMEOUT);
    return 0;
  }

  memcpy(buffer, (uint8_t *)live->read_packet->Buffer+bpfh->bh_hdrlen, (size_t)received);

  return received;
}

ssize_t
netpacket_live_send(netpacket_live_t *live, const void *buffer, size_t length) {
  ssize_t sent = -1;
 // uint8_t *write_buffer = NULL;

/*
  if (length > live->write_buffer_length && !(write_buffer = (uint8_t *)realloc(live->write_buffer, sizeof(uint8_t)*length))) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    return -1;
  }
  if (write_buffer) {
    live->write_buffer_length = length;
    live->write_buffer = write_buffer;
    PacketInitPacket(live->write_packet, (PVOID)live->write_buffer, (UINT)live->write_buffer_length);
  }
*/

  memset(live->write_packet->Buffer, 0, live->write_packet->Length);

  memcpy(live->write_packet->Buffer, buffer, length);
  live->write_packet->Length = length;

  if (!PacketSendPacket(live->adapter, live->write_packet, true)) {
    netpacket_seterror(NETPACKET_ESYSCALL);
    goto _return;
  }

  live->write_packet->Length = live->write_buffer_length;

  sent = (ssize_t)length;

_return:
  return sent;
}

void
netpacket_live_close(netpacket_live_t *live) {
  if (live) {
    if (live->write_packet)
      PacketFreePacket(live->write_packet), live->write_packet = NULL;
    if (live->write_buffer)
      free(live->write_buffer), live->write_buffer = NULL;

    if (live->read_packet)
      PacketFreePacket(live->read_packet), live->read_packet = NULL;
    if (live->read_buffer)
      free(live->read_buffer), live->read_buffer = NULL;

    PacketCloseAdapter(live->adapter);
    free(live);
  }
}
