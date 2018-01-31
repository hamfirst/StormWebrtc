#pragma once

#include <cstdint>


struct DataChannelOpenHeader
{
  uint8_t m_MessageType;
  uint8_t m_ChannelType;
  uint16_t m_Priority;
  uint32_t m_ReliabilityParameter;
  uint16_t m_LabelLength;
  uint16_t m_ProtocolLength;
};

enum DataMessageType
{
  kNone,
  kControl,
  kBinary,
  kText,
};
