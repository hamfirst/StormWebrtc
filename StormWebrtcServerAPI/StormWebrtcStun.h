#pragma once

#include <stdint.h>

#pragma pack(push, 1)

struct StunHeader
{
  uint16_t m_Type;
  uint16_t m_Length;
  uint32_t m_Cookie;
  uint32_t m_TransactionId[3];
};

struct StunAddrAttribute
{
  uint8_t m_Zero;
  uint8_t m_Family;
  uint16_t m_Port;
  uint32_t m_Addr;
};

struct StunRequest
{
  const StunHeader * m_Header;
  bool m_IsBindingRequest;

  const char * m_UserName;
  int m_UserNameLength;

  const char * m_MessageIntegrity;
  int m_MessageIntegrityLength;
  int m_MessageIntegrityDataLength;

  const char * m_Fingerprint;
  int m_FingerprintLength;
  int m_FingerprintDataLength;
};

struct StunResponse
{
  uint16_t m_Len;
  uint8_t m_Buffer[1024];
};

bool StunReadRequest(const void * data, int recvlen, StunRequest & req);
void StunCreateResponse(const StunRequest & req, StunResponse & resp, uint32_t host, uint16_t port);
void StunCreateBindingRequest(const StunRequest & req, StunResponse & resp, uint32_t host, uint16_t port);
void StunCreateErrorResponse(const StunRequest & req, StunResponse & resp);
#pragma pack(pop)
