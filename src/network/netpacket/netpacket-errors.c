#include "netpacket-errors.h"

#if defined __linux__ || defined __linux
#include <network/sockets/sockets-errors.h>
#endif

#if defined __cplusplus && __cplusplus < 201103L
  #define thread_local __thread
#endif

#if !defined __cplusplus
  #define thread_local _Thread_local
#endif


thread_local netpacket_error_t netpacket_error;


const char *
netpacket_getstrerror(netpacket_error_t error) {
  switch (error) {
#if defined __linux__ || defined __linux
    case NETPACKET_EPROTOCOL:
      return "network protocol not supported";

    case NETPACKET_ESOCKET:
      return socket_getstrerror(socket_geterror());
#endif

    case NETPACKET_ETIMEOUT:
      return "operation timed out";

    case NETPACKET_ENOSUPPORT:
      return "there is no support/implementation for the system";

    case NETPACKET_ESYSCALL:
      return syscall_getstrerrno(syscall_geterrno());
  }

  return "unknown error";
}

netpacket_error_t
netpacket_geterror(void) {
  return netpacket_error;
}

void
netpacket_seterror(netpacket_error_t error) {
  netpacket_error = error;
}
