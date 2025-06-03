#ifndef _NETWORK_NETPACKET_NETPACKET_ERRORS_H
#define _NETWORK_NETPACKET_NETPACKET_ERRORS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <syscall-errno/syscall-errno.h>


typedef enum {
  NETPACKET_ESYSCALL = -5, NETPACKET_ENOSUPPORT, NETPACKET_ETIMEOUT,
#if defined __linux__ || defined __linux
  NETPACKET_EPROTOCOL, NETPACKET_ESOCKET,
#endif
} netpacket_error_t;


extern const char *netpacket_getstrerror(netpacket_error_t);
extern netpacket_error_t netpacket_geterror(void);
extern void netpacket_seterror(netpacket_error_t);

#ifdef __cplusplus
}
#endif

#endif
