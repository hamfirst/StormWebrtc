#pragma once

#include <memory>
#include <vector>
#include <cstdlib>

enum class StormWebrtcClientStreamType : uint8_t
{
  kReliable,
  kUnreliable,
};

using StormWebrtcClientChannelList = std::vector<StormWebrtcClientStreamType>;

struct StormWebrtcPacketDeleter
{
  void operator()(uint8_t *p) { free(p); }
};

struct StormWebrtcClientPacket
{
  std::unique_ptr<uint8_t[], StormWebrtcPacketDeleter> m_Buffer;
  int m_Length;
  int m_Stream;
  bool m_SenderChannel;
};
