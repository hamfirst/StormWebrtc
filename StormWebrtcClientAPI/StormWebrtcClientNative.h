#pragma once


#ifndef _WEB

#include <memory>
#include <queue>
#include <vector>
#include <cstdlib>

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

#include "usrsctplib/usrsctp.h"

#include "StormWebrtc/StormWebrtcConnection.h"
#include "StormWebrtc/StormWebrtcDataChannel.h"
#include "StormWebrtcClientAPI/StormWebrtcClient.h"

enum class StormWebrtcClientNativeState
{
  kDisconnected,
  kInitialHello,
  kSecondHello,
  kSCTPConnect,
  kChannelInit,
  kConnected,
};

class StormWebrtcClientNative : public StormWebrtcClient
{
public:
  StormWebrtcClientNative(const StormWebrtcClientChannelList & in_channels, const StormWebrtcClientChannelList & out_channels);
  StormWebrtcClientNative(const StormWebrtcClientChannelList & in_channels, const StormWebrtcClientChannelList & out_channels, const char * ipaddr, int port, const char * fingerprint);
  StormWebrtcClientNative(const StormWebrtcClientNative & rhs) = delete;
  StormWebrtcClientNative(StormWebrtcClientNative && rhs) = delete;
  ~StormWebrtcClientNative();

  StormWebrtcClientNative & operator = (const StormWebrtcClientNative & rhs) = delete;
  StormWebrtcClientNative & operator = (StormWebrtcClientNative && rhs) = delete;

  virtual void StartConnect(const char * ipaddr, int port, const char * fingerprint) override;
  virtual void Update() override;

  virtual bool IsConnected() override;
  virtual bool IsConnecting() override;
  virtual void Close() override;

  virtual void SendPacket(int stream, bool sender_channel, const void * data, std::size_t data_len) override;
  virtual bool PollPacket(StormWebrtcClientPacket & out_packet) override;

private:

  void StartSctpConnect();
  void SendInitialDataChannels();
  void CheckConnectedState();
  void NotifySocketConnected();

  void SendData(DataMessageType type, int sid, bool reliable, const void * data, std::size_t length);

  void HandleSctpPacket(void * buffer, std::size_t length, int stream, int ppid);
  void HandleSctpAssociationChange(const sctp_assoc_change & change);

private:
  int m_Socket;
  bool m_Connected;
  bool m_Connecting;

  StormWebrtcClientNativeState m_State;

  StormWebrtcClientChannelList m_InChannels;
  StormWebrtcClientChannelList m_OutChannels;

  std::queue<StormWebrtcClientPacket> m_PendingPackets;

private:

  mbedtls_x509_crt m_CA;
  mbedtls_entropy_context m_Entropy;
  mbedtls_ctr_drbg_context m_CtrDrbg;

  mbedtls_ssl_config m_SSLConfig;
  StormWebrtcConnection m_Connection;
};

#endif