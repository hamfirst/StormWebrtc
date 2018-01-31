
#include "StormWebrtcServerAPI/StormWebrtcServerImpl.h"



StormWebrtcServer::~StormWebrtcServer()
{

}

std::unique_ptr<StormWebrtcServer> CreateStormWebrtcServer(const StormWebrtcServerSettings & settings)
{
  return std::make_unique<StormWebrtcServerImpl>(settings);
}

