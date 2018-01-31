#pragma once


#include "StormWebrtcClientAPI/StormWebrtcClientTypes.h"

class StormWebrtcClient
{
public:
  virtual ~StormWebrtcClient();

  virtual void StartConnect(const char * ipaddr, int port, const char * fingerprint) = 0;
  virtual void Update() = 0;

  virtual bool IsConnected() = 0;
  virtual bool IsConnecting() = 0;
  virtual void Close() = 0;

  virtual void SendPacket(int stream, bool sender_channel, const void * data, std::size_t data_len) = 0;
  virtual bool PollPacket(StormWebrtcClientPacket & out_packet) = 0;
};

std::unique_ptr<StormWebrtcClient> CreateStormWebrtcClient(const StormWebrtcClientChannelList & in_channels, const StormWebrtcClientChannelList & out_channels);
std::unique_ptr<StormWebrtcClient> CreateStormWebrtcClient(const StormWebrtcClientChannelList & in_channels, const StormWebrtcClientChannelList & out_channels, const char * ipaddr, int port, const char * fingerprint);
