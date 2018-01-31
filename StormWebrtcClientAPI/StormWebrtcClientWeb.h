#pragma once

#include <memory>
#include <queue>
#include <vector>
#include <chrono>
#include <cstdlib>

#include "StormWebrtcClientAPI/StormWebrtcClient.h"

class StormWebrtcClientWeb : public StormWebrtcClient
{
public:
  StormWebrtcClientWeb(const StormWebrtcClientChannelList & in_channels, const StormWebrtcClientChannelList & out_channels);
  StormWebrtcClientWeb(const StormWebrtcClientChannelList & in_channels, const StormWebrtcClientChannelList & out_channels, const char * ipaddr, int port, const char * fingerprint);
  StormWebrtcClientWeb(const StormWebrtcClientWeb & rhs) = delete;
  StormWebrtcClientWeb(StormWebrtcClientWeb && rhs)  noexcept;
  ~StormWebrtcClientWeb();

  StormWebrtcClientWeb & operator = (const StormWebrtcClientWeb & rhs) = delete;
  StormWebrtcClientWeb & operator = (StormWebrtcClientWeb && rhs) noexcept;

  virtual void StartConnect(const char * ipaddr, int port, const char * fingerprint) override;
  virtual void Update() override;

  virtual bool IsConnected() override;
  virtual bool IsConnecting() override;
  virtual void Close() override;

  virtual void SendPacket(int stream, bool sender_channel, const void * data, std::size_t data_len) override;
  virtual bool PollPacket(StormWebrtcClientPacket & out_packet) override;

private:
  int m_Socket;
  bool m_Connected;
  bool m_Connecting;

  std::chrono::system_clock::time_point m_LastMessage;

  StormWebrtcClientChannelList m_InChannels;
  StormWebrtcClientChannelList m_OutChannels;

  std::queue<StormWebrtcClientPacket> m_PendingPackets;

public:

  void SetConnected(bool connected);
  void GotMessage(int stream, bool sender, void * data, int length);
};


