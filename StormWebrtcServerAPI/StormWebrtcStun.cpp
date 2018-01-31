
#include "StormWebrtcServerAPI/StormWebrtcStun.h"

#include "mbedtls/md.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef _MSC_VER
#include <winsock.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

static unsigned int StunCRCTable[] = {
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
  0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
  0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
  0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
  0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
  0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
  0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
  0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
  0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
  0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
  0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
  0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
  0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
  0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
  0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
  0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
  0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
  0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
  0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
  0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
  0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
  0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
  0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
  0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
  0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
  0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
  0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
  0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
  0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
  0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
  0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
  0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
  0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
  0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
  0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
  0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
  0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
  0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
  0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
  0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
  0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
  0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
  0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t StunCRC32Step(uint8_t c, uint32_t crc)
{
  return (StunCRCTable[((crc) ^ (c)) & 0xff] ^ ((crc) >> 8));
}

uint32_t StunCRC32(uint8_t * ptr, uint32_t len)
{
  uint32_t c = 0xFFFFFFFF;

  for (; len; --len, ++ptr) 
  { 
    c = StunCRC32Step(*ptr, c); 
  }

  return ~c;
}

bool StunReadRequest(const void * data, int recvlen, StunRequest & req)
{
  req = {};

  if (recvlen < sizeof(StunHeader))
  {
    return false;
  }

  StunHeader * header = (StunHeader *)data;
  if (header->m_Cookie != 0x42a41221)
  {
    return false;
  }

  if (htons(header->m_Length) != recvlen - 20)
  {
    return false;
  }

  req.m_Header = header;
  auto type = htons(header->m_Type);
  req.m_IsBindingRequest = (type == 0x0001); // BINDING REQUEST

  int stun_len = htons(header->m_Length);
  char * attr_start = (char *)(header + 1);

  auto first_attr_ptr = attr_start;

  while (stun_len > 0)
  {
    if (stun_len < 4)
    {
      return false;
    }

    uint16_t attr_type = htons(*(uint16_t *)attr_start);
    attr_start += 2;
    stun_len -= 2;

    uint16_t attr_len = htons(*(uint16_t *)attr_start);
    attr_start += 2;
    stun_len -= 2;

    int padding = attr_len % 4;
    if (padding != 0)
    {
      attr_len += 4 - padding;
    }

    if (attr_len > stun_len)
    {
      return false;
    }

    if (req.m_Fingerprint != nullptr)
    {
      return false;
    }

    switch (attr_type)
    {
    case 0x0006:
      //printf(" Attribute: USERNAME!\n");
      req.m_UserName = (const char *)attr_start;
      req.m_UserNameLength = attr_len;
      break;
    case 0x0008:
      //printf(" Attribute: MESSAGE-INTEGRITY!\n");
      req.m_MessageIntegrity = (const char *)attr_start;
      req.m_MessageIntegrityLength = attr_len;
      req.m_MessageIntegrityDataLength = (int)(((char *)attr_start - 4) - (char *)data);
      break;
    case 0x8028:
      //printf(" Attribute: FINGERPRINT!\n");
      req.m_Fingerprint = (const char *)attr_start;
      req.m_FingerprintLength = attr_len;
      req.m_FingerprintDataLength = (int)(((char *)attr_start - 4) - (char *)data);
      break;
    }

    stun_len -= attr_len;
    attr_start += attr_len;
  }

  if (req.m_MessageIntegrity)
  {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    auto original_length = header->m_Length;
    header->m_Length = htons(req.m_MessageIntegrityDataLength + 4 + req.m_MessageIntegrityLength - 20);

    uint8_t buffer[20];

    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
    mbedtls_md_hmac_starts(&ctx, (unsigned char *)"3S0OeHDz16aoWRK4tnALIsebH4nk9olF", 32);
    mbedtls_md_hmac_update(&ctx, (unsigned char *)data, req.m_MessageIntegrityDataLength);
    mbedtls_md_hmac_finish(&ctx, buffer);

    mbedtls_md_free(&ctx);

    header->m_Length = original_length;

    if (memcmp(buffer, req.m_MessageIntegrity, 20) != 0)
    {
      //printf(" Invalid message integrity check\n");
      return false;
    }
  }

  if (req.m_Fingerprint)
  {
    if (req.m_FingerprintLength != 4)
    {
      //printf(" Fingerprint length must be 4\n");
      return false;
    }

    uint32_t fingerprint_val = *(uint32_t *)req.m_Fingerprint;

    auto fingerprint_start = (uint8_t *)data;
    auto fingerpint_len = req.m_Fingerprint - (char *)fingerprint_start - 4;

    auto crc = StunCRC32(fingerprint_start, (uint32_t)fingerpint_len);
    crc ^= 0x5354554e;

    if (crc != ntohl(fingerprint_val))
    {
      //printf(" Invalid fingerpint\n");
      return false;
    }
  }

  return true;
}

void StunAddUsernameAttribute(StunResponse & resp, const char * inc_username, int username_len)
{
  uint16_t * attr_type = (uint16_t *)(&resp.m_Buffer[resp.m_Len]);
  *attr_type = htons(0x0006); // USERNAME
  uint16_t * attr_len = (attr_type + 1);
  *attr_len = htons(username_len);
  char * attr_start = (char *)(attr_len + 1);
  memset(attr_start, 0, username_len);
  
  bool found_colon = false;
  for (int index = 0; index < username_len; ++index)
  {
    if (inc_username[index] == ':')
    {
      int rlen = 0;
      for (int src = index + 1, dst = 0; src < username_len && inc_username[src] != 0; ++src, ++dst, ++rlen)
      {
        attr_start[dst] = inc_username[src];
      }

      attr_start[rlen] = ':';
      for (int src = 0, dst = rlen + 1; src < index; ++src, ++dst)
      {
        attr_start[dst] = inc_username[src];
      }

      found_colon = true;
      break;
    }
  }

  if (found_colon == false)
  {
    strncpy(attr_start, inc_username, username_len);
  }

  resp.m_Len += 4 + username_len;
}

void StunAddIceControlled(StunResponse & resp)
{
  uint16_t * attr_type = (uint16_t *)(&resp.m_Buffer[resp.m_Len]);
  *attr_type = htons(0x8029); // ICE-CONTROLLED
  uint16_t * attr_len = (attr_type + 1);
  *attr_len = htons(8);
  uint32_t * attr_start = (uint32_t *)(attr_len + 1);
  attr_start[0] = rand();
  attr_start[1] = rand();

  resp.m_Len += 12;
}

void StunAddAddressAttribute(StunResponse & resp, uint32_t host, uint16_t port)
{
  uint16_t * attr_type = (uint16_t *)(&resp.m_Buffer[resp.m_Len]);
  *attr_type = htons(0x0020); // XOR-MAPPED-ADDRESS
  uint16_t * attr_len = (attr_type + 1);
  *attr_len = htons(sizeof(StunAddrAttribute));
  char * attr_start = (char *)(attr_len + 1);
  StunAddrAttribute * addr_attr = (StunAddrAttribute *)attr_start;
  addr_attr->m_Zero = 0;
  addr_attr->m_Family = 1; // ipv4
  addr_attr->m_Port = port ^ 0x1221;
  addr_attr->m_Addr = host ^ 0x42A41221;

  resp.m_Len += 4 + sizeof(StunAddrAttribute);
}

void StunAddMessageIntegrityAttribute(StunResponse & resp, StunHeader * response_header)
{
  uint16_t * attr_type = (uint16_t *)(&resp.m_Buffer[resp.m_Len]);
  *attr_type = htons(0x0008); // MESSAGE-INTEGRITY
  uint16_t * attr_len = (attr_type + 1);
  *attr_len = htons(20);
  char * attr_start = (char *)(attr_len + 1);

  response_header->m_Length = htons(resp.m_Len + 24 - 20); // Length doesn't consider the stun header, but we also add in the length of the integrity check
  
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);

  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
  mbedtls_md_hmac_starts(&ctx, (unsigned char *)"3S0OeHDz16aoWRK4tnALIsebH4nk9olF", 32);
  mbedtls_md_hmac_update(&ctx, (unsigned char *)response_header, resp.m_Len);
  mbedtls_md_hmac_finish(&ctx, (unsigned char *)attr_start);

  mbedtls_md_free(&ctx);

  resp.m_Len += 24;
}

void StunAddFingerprintAttribute(StunResponse & resp, StunHeader * response_header)
{
  uint16_t * attr_type = (uint16_t *)(&resp.m_Buffer[resp.m_Len]);
  *attr_type = htons(0x8028); // FINGERPRINT
  uint16_t * attr_len = (attr_type + 1);
  *attr_len = htons(4);
  uint32_t * attr = (uint32_t *)(attr_len + 1);

  response_header->m_Length = htons(resp.m_Len + 8 - 20); // Length doesn't consider the stun header, but we also add in the length of the fingerprint

  auto crc = StunCRC32((uint8_t *)response_header, resp.m_Len);
  crc ^= 0x5354554e;

  *attr = ntohl(crc);

  resp.m_Len += 8;
}

void StunCreateResponse(const StunRequest & req, StunResponse & resp, uint32_t host, uint16_t port)
{
  StunHeader * response_header = (StunHeader *)resp.m_Buffer;
  response_header->m_Type = htons(0x0101); // binding response
  response_header->m_Cookie = req.m_Header->m_Cookie;
  memcpy(&response_header->m_TransactionId, &req.m_Header->m_TransactionId, sizeof(StunHeader::m_TransactionId));
  resp.m_Len = sizeof(StunHeader);

  StunAddAddressAttribute(resp, host, port);
  StunAddIceControlled(resp);
  StunAddMessageIntegrityAttribute(resp, response_header);
  StunAddFingerprintAttribute(resp, response_header);
}

void StunCreateErrorResponse(const StunRequest & req, StunResponse & resp)
{
  StunHeader * response_header = (StunHeader *)resp.m_Buffer;
  memcpy(&response_header->m_TransactionId, &req.m_Header->m_TransactionId, sizeof(StunHeader::m_TransactionId));
  response_header->m_Cookie = req.m_Header->m_Cookie;
  response_header->m_Type = htons(0x0111); // binding error
  resp.m_Len = sizeof(StunHeader);

  uint16_t * attr_type = (uint16_t *)(&resp.m_Buffer[resp.m_Len]);
  *attr_type = 0x0009; // ERROR-CODE
  uint16_t * attr_len = (attr_type + 1);
  *attr_len = 4;
  char * attr_start = (char *)(attr_len + 1);
  uint32_t error_code = 0x00040000;
  memcpy(attr_start, &error_code, 4);

  resp.m_Len += 4 + 4;
}

void StunCreateBindingRequest(const StunRequest & req, StunResponse & resp, uint32_t host, uint16_t port)
{
  StunHeader * response_header = (StunHeader *)resp.m_Buffer;
  response_header->m_Type = htons(0x0001); // binding request
  response_header->m_Cookie = req.m_Header->m_Cookie;

  for (int index = 0; index < 3; ++index)
  {
    response_header->m_TransactionId[index] = rand();
  }

  resp.m_Len = sizeof(StunHeader);

  StunAddUsernameAttribute(resp, req.m_UserName, req.m_UserNameLength);
  StunAddIceControlled(resp);
  StunAddAddressAttribute(resp, host, port);
  StunAddMessageIntegrityAttribute(resp, response_header);
  StunAddFingerprintAttribute(resp, response_header);
}
