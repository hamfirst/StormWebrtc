#pragma once

#include <vector>
#include <chrono>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/net.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#include "usrsctplib/usrsctp.h"

//#define STORMWEBRTC_USE_THREADS


class StormWebrtcServerImpl;

struct StormWebrtcConnection
{
#ifdef STORMWEBRTC_USE_THREADS
  std::recursive_mutex m_Mutex;
#endif

  bool m_Allocated = false;
  bool m_Connected = false;
  bool m_CreatedDataChannels = false;
  bool m_HasAssoc = false;
  uint16_t m_SlotIndex = 0;
  uint16_t m_Generation = 0;
  mbedtls_ssl_context m_SSLContext;
  mbedtls_timing_delay_context m_Timer;
  uint32_t m_RemoteIp;
  uint16_t m_RemotePort;
  StormWebrtcServerImpl * m_ServerImpl;
  struct socket * m_SctpSocket;
  sctp_assoc_t m_SctpAssoc;
  std::chrono::system_clock::time_point m_LastMessage;

  std::vector<bool> m_IncStreamCreated;
  std::vector<bool> m_OutStreamCreated;
};
