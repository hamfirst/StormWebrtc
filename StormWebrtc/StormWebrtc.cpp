
#include <cstdio>
#include <cstdarg>

#include "StormWebrtc/StormWebrtcConnection.h"

static void debug_printf(const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  vprintf(format, ap);
  va_end(ap);
};

void StormWebrtcStaticInit()
{
  auto sctp_send_cb = [](void * addr, void * buffer, std::size_t length, uint8_t tos, uint8_t df) -> int
  {
    auto & connection = *static_cast<StormWebrtcConnection *>(addr);

#ifdef STORMWEBRTC_USE_THREADS
    std::unique_lock<std::recursive_mutex> connection_lock(connection.m_Mutex);
#endif

    if (connection.m_Allocated == false || connection.m_SSLContext.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      return 0;
    }

    auto data = (uint8_t *)buffer;
    auto data_size = length;

    while (data_size > 0)
    {
      auto data_wrote = mbedtls_ssl_write(&connection.m_SSLContext, (uint8_t *)buffer, length);
      if (data_wrote > 0)
      {
        data_size -= data_wrote;
        data += data_wrote;
      }
      else
      {
        return 1;
      }
    }

    return 0;
  };

#ifdef STORMWEBRTC_USE_THREADS
  usrsctp_init(0, sctp_send_cb, debug_printf);
#else
  usrsctp_init_nothreads(0, sctp_send_cb, debug_printf);
#endif

  usrsctp_sysctl_set_sctp_blackhole(2);
}

void StormWebrtcStaticCleanup()
{
  usrsctp_finish();
}
