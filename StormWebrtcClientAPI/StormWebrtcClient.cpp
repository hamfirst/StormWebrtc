
#include "StormWebrtcClientAPI/StormWebrtcClient.h"

#ifdef _WEB

#include "StormWebrtcClientWeb.h"
using StormWebrtcClientClass = StormWebrtcClientWeb;

#else
#include "StormWebrtcClientNative.h"
using StormWebrtcClientClass = StormWebrtcClientNative;

#endif

StormWebrtcClient::~StormWebrtcClient()
{

}

std::unique_ptr<StormWebrtcClient> CreateStormWebrtcClient(const StormWebrtcClientChannelList & in_channels, const StormWebrtcClientChannelList & out_channels)
{
  return std::make_unique<StormWebrtcClientClass>(in_channels, out_channels);
}

std::unique_ptr<StormWebrtcClient> CreateStormWebrtcClient(const StormWebrtcClientChannelList & in_channels, const StormWebrtcClientChannelList & out_channels, const char * ipaddr, int port, const char * fingerprint)
{
  return std::make_unique<StormWebrtcClientClass>(in_channels, out_channels, ipaddr, port, fingerprint);
}
