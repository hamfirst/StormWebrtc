
#include "StormWebrtcClientAPI/StormWebrtcClient.h"

#include <string>

#ifdef EMSCRIPTEN
#include <emscripten.h>
#include <emscripten/html5.h>
#else


template <typename T>
void emscripten_set_main_loop(T && t, int fps, bool bs)
{

}

#endif

std::unique_ptr<StormWebrtcClient> m_Client;
bool m_Connected = false;

int main()
{
  StormWebrtcClientChannelList in_channels = { StormWebrtcClientStreamType::kReliable };
  StormWebrtcClientChannelList out_channels = { StormWebrtcClientStreamType::kReliable };
  m_Client = std::make_unique<StormWebrtcClient>(in_channels, out_channels);

  printf("Attempting to connect\n");
  m_Client->StartConnect("127.0.0.1", 61200, "78:0A:DC:3D:8D:75:D6:A8:D3:93:E9:2D:3C:78:6C:7E:E8:DB:A5:7F:7F:FD:3E:4F:09:05:93:7E:6D:60:15:67");

  emscripten_set_main_loop([]()
  {
    if (m_Client->IsConnected() && m_Connected == false)
    {
      m_Connected = true;
      m_Client->SendPacket(0, "hello", 5);
      printf("Connected\n");
    }

    if (m_Client->IsConnected() == false && m_Connected)
    {
      m_Connected = false;
      printf("Disconnected\n");
    }

    if (m_Connected)
    {
      StormWebrtcPacket packet;
      while (m_Client->PollPacket(packet))
      {
        std::string str((char *)packet.m_Buffer.get(), packet.m_Length);

        printf("Got data: %s\n", str.data());
      }
    }


  }, 0, false);

  return 0;
}
