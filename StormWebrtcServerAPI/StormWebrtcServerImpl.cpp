
#include "StormWebrtcServerAPI/StormWebrtcStun.h"
#include "StormWebrtcServerAPI/StormWebrtcServerImpl.h"


StormWebrtcServerImpl::StormWebrtcServerImpl(const StormWebrtcServerSettings & settings) :
  m_ServerSocket(m_IoService),
  m_Connections(std::make_unique<StormWebrtcConnection[]>(settings.m_MaxConnections)),
  m_NumConnections(settings.m_MaxConnections)
{
  m_InStreams = settings.m_InStreams;
  m_OutStreams = settings.m_OutStreams;

  for (std::size_t index = 0; index < m_NumConnections; ++index)
  {
    m_Connections[index].m_IncStreamCreated.resize(m_InStreams.size());
    m_Connections[index].m_OutStreamCreated.resize(m_OutStreams.size());
  }

  mbedtls_x509_crt_init(&m_Cert);
  mbedtls_ssl_config_init(&m_Config);
  mbedtls_pk_init(&m_Pk);
  mbedtls_entropy_init(&m_Entropy);
  mbedtls_ctr_drbg_init(&m_CtrDrbg);
  mbedtls_ssl_cookie_init(&m_CookieCtx);

#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_init(&m_Cache);
#endif

  auto cert_file = LoadCertificateFile(settings.m_CertFile);
  auto ret = mbedtls_x509_crt_parse(&m_Cert, (const unsigned char *)cert_file.data(), cert_file.size());
  if (ret != 0)
  {
    throw std::runtime_error(std::string("mbedtls_x509_crt_parse returned " + std::to_string(ret)));
  }

  auto key_file = LoadCertificateFile(settings.m_KeyFile);
  ret = mbedtls_pk_parse_key(&m_Pk, (const unsigned char *)key_file.data(), key_file.size(), NULL, 0);
  if (ret != 0)
  {
    throw std::runtime_error(std::string("mbedtls_pk_parse_key returned " + std::to_string(ret)));
  }

  const char * pers = "StormWebrtcServer";
  if ((ret = mbedtls_ctr_drbg_seed(&m_CtrDrbg, mbedtls_entropy_func, &m_Entropy, (const unsigned char *)pers, strlen(pers))) != 0)
  {
    throw std::runtime_error(std::string("mbedtls_ctr_drbg_seed returned " + std::to_string(ret)));
  }

  if ((ret = mbedtls_ssl_config_defaults(&m_Config,
      MBEDTLS_SSL_IS_SERVER,
      MBEDTLS_SSL_TRANSPORT_DATAGRAM,
      MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
  {
    throw std::runtime_error(std::string("mbedtls_ssl_config_defaults returned " + std::to_string(ret)));
  }

  mbedtls_ssl_conf_rng(&m_Config, mbedtls_ctr_drbg_random, &m_CtrDrbg);
  mbedtls_ssl_conf_authmode(&m_Config, MBEDTLS_SSL_VERIFY_NONE);

#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_conf_session_cache(&m_Config, &m_Cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
#endif

  mbedtls_ssl_conf_ca_chain(&m_Config, m_Cert.next, NULL);
  if ((ret = mbedtls_ssl_conf_own_cert(&m_Config, &m_Cert, &m_Pk)) != 0)
  {
    throw std::runtime_error(std::string("mbedtls_ssl_conf_own_cert returned " + std::to_string(ret)));
  }

  if ((ret = mbedtls_ssl_cookie_setup(&m_CookieCtx, mbedtls_ctr_drbg_random, &m_CtrDrbg)) != 0)
  {
    throw std::runtime_error(std::string("mbedtls_ssl_cookie_setup returned " + std::to_string(ret)));
  }

  mbedtls_ssl_conf_dtls_cookies(&m_Config, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &m_CookieCtx);

  auto debug_func = [](void *ctx, int level, const char *file, int line, const char *str)
  {
    fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *)ctx);
  };

  mbedtls_ssl_conf_dbg(&m_Config, debug_func, stdout);
  //mbedtls_debug_set_threshold(5);

  auto sctp_receive_cb = [](struct socket *sock, union sctp_sockstore addr, void *data,
    size_t datalen, struct sctp_rcvinfo rcv, int flags, void *ulp_info) -> int
  {
    auto & connection = *static_cast<StormWebrtcConnection *>(addr.sconn.sconn_addr);

#ifdef STORMWEBRTC_USE_THREADS
    std::unique_lock<std::recursive_mutex> connection_lock(connection.m_Mutex);
#endif

    if (flags & MSG_NOTIFICATION)
    {
      auto notification = (sctp_notification *)data;
      switch (notification->sn_header.sn_type) 
      {
      case SCTP_ASSOC_CHANGE:
        connection.m_ServerImpl->HandleSctpAssociationChange(connection, notification->sn_assoc_change);
        break;
      case SCTP_SENDER_DRY_EVENT:
        //SetReadyToSendData();
        break;
      case SCTP_STREAM_RESET_EVENT:
        //OnStreamResetEvent(&notification.sn_strreset_event);
        break;
      }
    }
    else
    {
      connection.m_ServerImpl->HandleSctpPacket(connection, data, datalen, rcv.rcv_sid, rcv.rcv_ppid);
    }

    free(data);
    return 1;
  };

  auto send_thresh_cb = [](struct socket* sock, uint32_t sb_free) -> int
  {
    return 0;
  };

  m_SctpListenSocket = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, sctp_receive_cb, send_thresh_cb, usrsctp_sysctl_get_sctp_sendspace() / 2, this);
  if (m_SctpListenSocket == nullptr)
  {
    throw std::runtime_error(std::string("Could not create sctp socket"));
  }

  if (usrsctp_set_non_blocking(m_SctpListenSocket, 1) < 0)
  {
    throw std::runtime_error(std::string("Could not set sctp socket non blocking"));
  }

  linger linger_opt;
  linger_opt.l_onoff = 1;
  linger_opt.l_linger = 0;
  if (usrsctp_setsockopt(m_SctpListenSocket, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt))) 
  {
    throw std::runtime_error(std::string("Could not set sctp socket linger"));
  }

  struct sctp_assoc_value stream_rst;
  stream_rst.assoc_id = SCTP_ALL_ASSOC;
  stream_rst.assoc_value = 1;
  if (usrsctp_setsockopt(m_SctpListenSocket, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &stream_rst, sizeof(stream_rst)))
  {
    throw std::runtime_error(std::string("Could not set sctp socket stream reset"));
  }

  uint32_t nodelay = 1;
  if (usrsctp_setsockopt(m_SctpListenSocket, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof(nodelay))) 
  {
    throw std::runtime_error(std::string("Could not set sctp socket nodelay"));
  }

  int event_types[] = 
  { 
    SCTP_ASSOC_CHANGE,
    SCTP_PEER_ADDR_CHANGE,
    SCTP_SEND_FAILED_EVENT, 
    SCTP_SENDER_DRY_EVENT,
    SCTP_STREAM_RESET_EVENT 
  };

  struct sctp_event event = { 0 };
  event.se_assoc_id = SCTP_ALL_ASSOC;
  event.se_on = 1;
  for (size_t index = 0; index < 5; index++) 
  {
    event.se_type = event_types[index];
    if (usrsctp_setsockopt(m_SctpListenSocket, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0)
    {
      throw std::runtime_error(std::string("Could not set sctp socket event sub"));
    }
  }

  sockaddr_in sctp_listen_addr;
  memset((void *)&sctp_listen_addr, 0, sizeof(sctp_listen_addr));
  sctp_listen_addr.sin_family = AF_INET;
  sctp_listen_addr.sin_port = htons(5000);
  sctp_listen_addr.sin_addr.s_addr = INADDR_ANY;

  if (usrsctp_bind(m_SctpListenSocket, (struct sockaddr *)&sctp_listen_addr, sizeof(struct sockaddr_in)) < 0)
  {
    throw std::runtime_error(std::string("sctp bind error"));
  }

  if (usrsctp_listen(m_SctpListenSocket, 1) < 0)
  {
    throw std::runtime_error(std::string("sctp listen error"));
  }

  asio::error_code ec;
  m_ServerSocket.open(asio::ip::udp::v4());
  m_ServerSocket.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), settings.m_Port), ec);

  if (ec)
  {
    throw std::runtime_error(std::string("bind error"));
  }

  PrepareToRecv();

#ifndef STORMWEBRTC_USE_THREADS
  m_LastUpdate = std::chrono::system_clock::now();
#endif
}

StormWebrtcServerImpl::~StormWebrtcServerImpl()
{
  mbedtls_x509_crt_free(&m_Cert);
  mbedtls_pk_free(&m_Pk);
  mbedtls_entropy_free(&m_Entropy);
  mbedtls_ctr_drbg_free(&m_CtrDrbg);
  mbedtls_ssl_cookie_free(&m_CookieCtx);

#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_free(&m_Cache);
#endif

  for (std::size_t index = 0; index < m_NumConnections; ++index)
  {
    if (m_Connections[index].m_Allocated)
    {
      CleanupConnection(m_Connections[index], index);
    }
  }
}

void StormWebrtcServerImpl::Update()
{
  m_IoService.poll();

  if (m_IoService.stopped())
  {
    m_IoService.reset();
  }

  if (m_GotData)
  {
    m_GotData = false;
    PrepareToRecv();
  }

  auto now = std::chrono::system_clock::now();

#ifndef STORMWEBRTC_USE_THREADS
  auto time_passed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_LastUpdate).count();

  if (time_passed_ms > 1)
  {
    usrsctp_fire_timer((int)time_passed_ms);
    m_LastUpdate = now;
  }
#endif

  std::size_t connection_slot = 0;

  auto timeout = std::chrono::seconds(15);
  for (auto connection = &m_Connections[0], end = &m_Connections[m_NumConnections]; connection != end; ++connection, ++connection_slot)
  {
    if (connection->m_Allocated)
    {
      if (connection->m_SSLContext.state != MBEDTLS_SSL_HANDSHAKE_OVER)
      {
        UpdateHandshake(*connection, connection_slot);
      }

      auto time_passed_seconds = std::chrono::duration_cast<std::chrono::seconds>(now - connection->m_LastMessage);
      if (time_passed_seconds > timeout)
      {
        NotifySocketDisconnected(*connection);
      }
    }
  }
}

bool StormWebrtcServerImpl::PollEvent(StormWebrtcEvent & outp_event)
{
  if (m_InputQueue.size() == 0)
  {
    return false;
  }

  outp_event = std::move(m_InputQueue.front());
  m_InputQueue.pop();
  return true;
}

void StormWebrtcServerImpl::SendPacket(const StormWebrtcConnectionHandle & handle, const void * data, std::size_t length, std::size_t stream, bool sender)
{
  if (handle.m_SlotId >= m_NumConnections)
  {
    return;
  }

  auto & connection = m_Connections[handle.m_SlotId];

  if (connection.m_Allocated == false ||
      connection.m_Connected == false || 
      connection.m_Generation != handle.m_Generation)
  {
    return;
  }

  if (sender)
  {
    int stream_id = (int)stream * 2;

    switch (m_InStreams[stream])
    {
    case StormWebrtcStreamType::kReliable:
      SendData(m_Connections[handle.m_SlotId], DataMessageType::kBinary, stream_id, true, data, length);
      break;
    case StormWebrtcStreamType::kUnreliable:
      SendData(m_Connections[handle.m_SlotId], DataMessageType::kBinary, stream_id, false, data, length);
      break;
    }
  }
  else
  {
    int stream_id = (int)stream * 2 + 1;

    switch (m_OutStreams[stream])
    {
    case StormWebrtcStreamType::kReliable:
      SendData(m_Connections[handle.m_SlotId], DataMessageType::kBinary, stream_id, true, data, length);
      break;
    case StormWebrtcStreamType::kUnreliable:
      SendData(m_Connections[handle.m_SlotId], DataMessageType::kBinary, stream_id, false, data, length);
      break;
    }
  }
}

void StormWebrtcServerImpl::ForceDisconnect(const StormWebrtcConnectionHandle & handle)
{
  if (handle.m_SlotId >= m_NumConnections)
  {
    return;
  }

  auto & connection = m_Connections[handle.m_SlotId];

  if (connection.m_Allocated == false ||
      connection.m_Connected == false ||
      connection.m_Generation != handle.m_Generation)
  {
    return;
  }

  NotifySocketDisconnected(connection);
}

std::string StormWebrtcServerImpl::LoadCertificateFile(const char * filename)
{
  auto fp = fopen(filename, "rb");
  if (fp == nullptr)
  {
    return{};
  }

  fseek(fp, 0, SEEK_END);
  auto size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  std::string str;
  str.resize(size + 1);
  fread((void *)str.data(), 1, size, fp);
  return str;
}

uint64_t StormWebrtcServerImpl::GetLookupIdForRemoteHost(uint32_t remote_ip, uint16_t remote_port)
{
  uint64_t lookup_id = remote_ip;
  lookup_id <<= 32;
  lookup_id += remote_port;
  return lookup_id;
}

void StormWebrtcServerImpl::InitConnection(StormWebrtcConnection & connection, std::size_t slot_index, uint32_t remote_ip, uint16_t remote_port)
{
#ifdef STORMWEBRTC_USE_THREADS
  std::unique_lock<std::recursive_mutex> connection_lock(connection.m_Mutex);
#endif

  int ret;
  if ((ret = mbedtls_ssl_setup(&connection.m_SSLContext, &m_Config)) != 0)
  {
    throw std::runtime_error(std::string("mbedtls_ssl_setup returned " + std::to_string(ret)));
  }

  mbedtls_ssl_set_timer_cb(&connection.m_SSLContext, &connection.m_Timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
  mbedtls_ssl_session_reset(&connection.m_SSLContext);

  auto send_callback = [](void * ctx, const unsigned char * data, size_t size) -> int
  {
    auto connection = (StormWebrtcConnection *)ctx;
    auto server = connection->m_ServerImpl;

    auto ip_addr = asio::ip::address_v4(connection->m_RemoteIp);
    return (int)server->m_ServerSocket.send_to(asio::buffer(data, size), asio::ip::udp::endpoint(ip_addr, connection->m_RemotePort));
  };

  auto recv_callback = [](void * ctx, unsigned char * data, size_t size) -> int
  {
    auto connection = (StormWebrtcConnection *)ctx;
    auto server = connection->m_ServerImpl;
    
    auto mem_avail = server->m_RecvDataLen - server->m_RecvDataOffset;
    if (mem_avail == 0)
    {
      return MBEDTLS_ERR_SSL_WANT_READ;
    }

    mem_avail = std::min(mem_avail, (uint32_t)size);

    memcpy(data, &server->m_RecvBuffer[server->m_RecvDataOffset], mem_avail);
    server->m_RecvDataOffset += mem_avail;
    return mem_avail;
  };

  auto recv_timeout_callback = [](void * ctx, unsigned char * data, size_t size, uint32_t timeout) -> int
  {
    auto connection = (StormWebrtcConnection *)ctx;
    auto server = connection->m_ServerImpl;

    auto mem_avail = server->m_RecvDataLen - server->m_RecvDataOffset;
    if (mem_avail == 0)
    {
      return MBEDTLS_ERR_SSL_WANT_READ;
    }

    mem_avail = std::min(mem_avail, (uint32_t)size);

    memcpy(data, &server->m_RecvBuffer[server->m_RecvDataOffset], mem_avail);
    server->m_RecvDataOffset += mem_avail;
    return mem_avail;
  };

  mbedtls_ssl_set_bio(&connection.m_SSLContext,
    &connection,
    send_callback,
    recv_callback,
    recv_timeout_callback);

  auto client_id = std::to_string(remote_ip);
  mbedtls_ssl_set_client_transport_id(&connection.m_SSLContext, (const unsigned char *)client_id.data(), client_id.size());

  connection.m_SlotIndex = (uint16_t)slot_index;
  connection.m_Generation++;
  connection.m_Allocated = true;
  connection.m_Connected = false;
  connection.m_HasAssoc = false;
  connection.m_RemoteIp = remote_ip;
  connection.m_RemotePort = remote_port;
  connection.m_ServerImpl = this;
  connection.m_SctpSocket = nullptr;
  connection.m_LastMessage = std::chrono::system_clock::now();

  for (auto && str : connection.m_IncStreamCreated)
  {
    str = false;
  }

  for (auto && str : connection.m_OutStreamCreated)
  {
    str = false;
  }

  uint64_t lookup_id = GetLookupIdForRemoteHost(remote_ip, remote_port);
  m_ConnectionMap.emplace(std::make_pair(lookup_id, slot_index));

  usrsctp_register_address(&connection);
}

void StormWebrtcServerImpl::CleanupConnection(StormWebrtcConnection & connection, std::size_t slot_index)
{
  connection.m_Allocated = false;
  connection.m_Generation++;
  mbedtls_ssl_close_notify(&connection.m_SSLContext);
  mbedtls_ssl_free(&connection.m_SSLContext);

  uint64_t lookup_id = GetLookupIdForRemoteHost(connection.m_RemoteIp, connection.m_RemotePort);
  m_ConnectionMap.erase(lookup_id);

  if (connection.m_SctpSocket)
  {
    usrsctp_close(connection.m_SctpSocket);
  }

  usrsctp_deregister_address(&connection);
}

void StormWebrtcServerImpl::UpdateHandshake(StormWebrtcConnection & connection, std::size_t slot_index)
{
  while (true)
  {
    auto ret = mbedtls_ssl_handshake_step(&connection.m_SSLContext);

    if (connection.m_SSLContext.state == MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      break;
    }

    if (ret == 0)
    {
      continue;
    }
    else if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
    {
      CleanupConnection(connection, slot_index);
      break;
    }
    else
    {
      break;
    }
  }
}

void StormWebrtcServerImpl::NotifySocketConnected(StormWebrtcConnection & connection)
{
  StormWebrtcEvent ev;
  ev.m_Type = StormWebrtcEventType::kConnected;
  ev.m_ConnectionHandle = StormWebrtcConnectionHandle{ connection.m_SlotIndex, connection.m_Generation };
  ev.m_RemoteAddr = connection.m_RemoteIp;
  ev.m_RemotePort = connection.m_RemotePort;
  m_InputQueue.push(std::move(ev));

  connection.m_Connected = true;
}

void StormWebrtcServerImpl::NotifySocketDisconnected(StormWebrtcConnection & connection)
{
  if (connection.m_Connected)
  {
    StormWebrtcEvent ev;
    ev.m_Type = StormWebrtcEventType::kDisconnected;
    ev.m_ConnectionHandle = StormWebrtcConnectionHandle{ connection.m_SlotIndex, connection.m_Generation };
    ev.m_RemoteAddr = connection.m_RemoteIp;
    ev.m_RemotePort = connection.m_RemotePort;
    m_InputQueue.push(std::move(ev));
  }

  CleanupConnection(connection, connection.m_SlotIndex);
}

void StormWebrtcServerImpl::HandleSctpPacket(StormWebrtcConnection & connection, void * buffer, std::size_t length, int stream, int ppid)
{
  BootstrapConnection(connection);

  if (stream % 2 == 0)
  {
    // Client stream
    auto stream_index = stream / 2;
    if (stream_index >= (int)m_InStreams.size())
    {
      return;
    }

    if (connection.m_IncStreamCreated[stream_index] == false)
    {
      if (length < sizeof(DataChannelOpenHeader))
      {
        return;
      }

      if (ppid != htonl(50))
      {
        return;
      }

      auto header = (DataChannelOpenHeader *)buffer;
      if (header->m_MessageType == 0x3) // DATA_CHANNEL_OPEN 
      {
        uint8_t ack = 0x2; //DATA_CHANNEL_ACK
        SendData(connection, DataMessageType::kControl, stream, true, &ack, 1);

        connection.m_IncStreamCreated[stream_index] = true;
        CheckConnectedState(connection);
      }
    }
    else if(connection.m_Connected)
    {
      StormWebrtcEvent ev;
      ev.m_Type = StormWebrtcEventType::kData;
      ev.m_ConnectionHandle = StormWebrtcConnectionHandle{ connection.m_SlotIndex, connection.m_Generation };
      ev.m_RemoteAddr = connection.m_RemoteIp;
      ev.m_RemotePort = connection.m_RemotePort;
      ev.m_DataSize = (uint16_t)length;
      ev.m_Buffer = std::make_unique<uint8_t[]>(length);
      ev.m_StreamIndex = stream_index;
      ev.m_SenderChannel = false;
      memcpy(ev.m_Buffer.get(), buffer, length);
      m_InputQueue.push(std::move(ev));
    }
  }
  else
  {
    // Server stream
    auto stream_index = stream / 2;
    if (stream_index >= (int)m_OutStreams.size())
    {
      return;
    }

    if (connection.m_OutStreamCreated[stream_index] == false)
    {
      if (length == 0)
      {
        return;
      }

      if (ppid != htonl(50))
      {
        return;
      }

      auto header = (DataChannelOpenHeader *)buffer;
      if (header->m_MessageType == 0x2)  // DATA_CHANNEL_ACK
      {
        connection.m_OutStreamCreated[stream_index] = true;
        CheckConnectedState(connection);
      }
    }
    else if (connection.m_Connected)
    {
      StormWebrtcEvent ev;
      ev.m_Type = StormWebrtcEventType::kData;
      ev.m_ConnectionHandle = StormWebrtcConnectionHandle{ connection.m_SlotIndex, connection.m_Generation };
      ev.m_RemoteAddr = connection.m_RemoteIp;
      ev.m_RemotePort = connection.m_RemotePort;
      ev.m_DataSize = (uint16_t)length;
      ev.m_Buffer = std::make_unique<uint8_t[]>(length);
      ev.m_StreamIndex = stream_index;
      ev.m_SenderChannel = true;
      memcpy(ev.m_Buffer.get(), buffer, length);
      m_InputQueue.push(std::move(ev));
    }
  }
}

void StormWebrtcServerImpl::HandleSctpAssociationChange(StormWebrtcConnection & connection, const sctp_assoc_change & change)
{
  if (change.sac_type == SCTP_ASSOC_CHANGE)
  {
    if (change.sac_state == SCTP_COMM_UP)
    {
      connection.m_SctpAssoc = change.sac_assoc_id;
      connection.m_HasAssoc = true;
      CheckConnectedState(connection);
    }
    else
    {
      connection.m_SctpSocket = nullptr;
      NotifySocketDisconnected(connection);
    }
  }
}


void StormWebrtcServerImpl::SendInitialDataChannels(StormWebrtcConnection & connection)
{
  if (connection.m_CreatedDataChannels == false)
  {
    for (std::size_t index = 0; index < m_OutStreams.size(); index++)
    {
      // Create the data channel
      auto data_channel_name = std::to_string(index);
      auto data_channel_name_len = data_channel_name.size();

      uint8_t data_channel_packet_buffer[128];
      auto data_channel_header = (DataChannelOpenHeader *)data_channel_packet_buffer;
      data_channel_header->m_MessageType = 0x03; // DATA_CHANNEL_OPEN 
      data_channel_header->m_Priority = 0;

      switch (m_OutStreams[index])
      {
      default:
      case StormWebrtcStreamType::kReliable:
        data_channel_header->m_ChannelType = 0x00; // DATA_CHANNEL_RELIABLE
        data_channel_header->m_ReliabilityParameter = 0;
        break;
      case StormWebrtcStreamType::kUnreliable:
        data_channel_header->m_ChannelType = 0x82; // DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED
        data_channel_header->m_ReliabilityParameter = 0;
        break;
      }

      data_channel_header->m_LabelLength = htons((uint16_t)data_channel_name_len);
      data_channel_header->m_ProtocolLength = 0;
      char * data_channel_name_buffer = (char *)(data_channel_header + 1);
      strcpy(data_channel_name_buffer, data_channel_name.data());

      SendData(connection, DataMessageType::kControl, (int)(index * 2) + 1, true, &data_channel_packet_buffer, sizeof(DataChannelOpenHeader) + (int)data_channel_name_len);
    }

    connection.m_CreatedDataChannels = true;
  }
}

void StormWebrtcServerImpl::BootstrapConnection(StormWebrtcConnection & connection)
{
  if (connection.m_HasAssoc && connection.m_SctpSocket == nullptr)
  {
    sockaddr_conn addr;
    socklen_t len = sizeof(sockaddr_conn);

    connection.m_SctpSocket = usrsctp_accept(m_SctpListenSocket, (sockaddr *)&addr, &len);
    SendInitialDataChannels(connection);
  }
}

void StormWebrtcServerImpl::CheckConnectedState(StormWebrtcConnection & connection)
{
  if (connection.m_Connected)
  {
    return;
  }

  for (auto && str : connection.m_IncStreamCreated)
  {
    if (str == false)
    {
      return;
    }
  }

  for (auto && str : connection.m_OutStreamCreated)
  {
    if (str == false)
    {
      return;
    }
  }

  NotifySocketConnected(connection);
}

void StormWebrtcServerImpl::PrepareToRecv()
{
  m_ServerSocket.async_receive_from(asio::buffer(m_RecvBuffer, kRecvBufferSize), m_RecvEndpoint, [this](const std::system_error & error, std::size_t bytes_transfered)
  {
    m_GotData = true;

    uint32_t remote_ip = m_RecvEndpoint.address().to_v4().to_ulong();
    uint16_t remote_port = m_RecvEndpoint.port();

    StunRequest req;
    if (StunReadRequest(m_RecvBuffer, (int)bytes_transfered, req))
    {
      if (req.m_IsBindingRequest)
      {
        StunResponse resp;

        StunCreateResponse(req, resp, remote_ip, remote_port);
        m_ServerSocket.send_to(asio::buffer(resp.m_Buffer, resp.m_Len), m_RecvEndpoint);
      }
      return;
    }

    auto lookup_id = GetLookupIdForRemoteHost(remote_ip, remote_port);
    auto connection_slot_itr = m_ConnectionMap.find(lookup_id);

    int connection_slot;

    if (connection_slot_itr == m_ConnectionMap.end())
    {
      if (bytes_transfered == 0)
      {
        return;
      }

      int slot = -1;
      for (uint32_t index = 0; index < m_NumConnections; ++index)
      {
        auto test_slot = (m_NextConnection + index) % m_NumConnections;
        if (m_Connections[index].m_Allocated == false)
        {
          slot = test_slot;
          break;
        }
      }

      if (slot == -1)
      {
        return;
      }

      InitConnection(m_Connections[slot], slot, remote_ip, remote_port);
      connection_slot = slot;
      m_NextConnection++;
    }
    else
    {
      connection_slot = (int)connection_slot_itr->second;
    }

    auto & connection = m_Connections[connection_slot];
    connection.m_LastMessage = std::chrono::system_clock::now();

#ifdef STORMWEBRTC_USE_THREADS
    std::unique_lock<std::recursive_mutex> connection_lock(connection.m_Mutex);
#endif

    if (bytes_transfered == 0)
    {
      NotifySocketDisconnected(connection);
      return;
    }

    m_RecvDataLen = (uint32_t)bytes_transfered;
    m_RecvDataOffset = 0;

    if (connection.m_SSLContext.state == MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      uint8_t packet[kRecvBufferSize];
      auto packet_size = mbedtls_ssl_read(&connection.m_SSLContext, packet, kRecvBufferSize);

      if (packet_size > 0)
      {
        usrsctp_conninput(&connection, packet, packet_size, 0);

        BootstrapConnection(connection);
      }
      else if (packet_size != MBEDTLS_ERR_SSL_WANT_READ && packet_size != MBEDTLS_ERR_SSL_WANT_WRITE)
      {
        NotifySocketDisconnected(connection);
      }
    }
    else
    {
      UpdateHandshake(connection, connection_slot);
    }

    m_RecvDataLen = 0;
    m_RecvDataOffset = 0;
  });
}

void StormWebrtcServerImpl::SendData(StormWebrtcConnection & connection, DataMessageType type, int sid, bool reliable, const void * data, std::size_t length)
{
  struct sctp_sendv_spa spa = { 0 };
  spa.sendv_flags |= SCTP_SEND_SNDINFO_VALID;
  spa.sendv_sndinfo.snd_sid = sid;

  if (connection.m_SctpSocket == nullptr)
  {
    return;
  }

  switch (type)
  {
  default:
  case DataMessageType::kNone:
    spa.sendv_sndinfo.snd_ppid = 0;
    break;
  case DataMessageType::kControl:
    spa.sendv_sndinfo.snd_ppid = htonl(50);
    break;
  case DataMessageType::kBinary:
    spa.sendv_sndinfo.snd_ppid = htonl(53);
    break;
  case DataMessageType::kText:
    spa.sendv_sndinfo.snd_ppid = htonl(51);
    break;
  }

  if (!reliable)
  {
    spa.sendv_sndinfo.snd_flags |= SCTP_UNORDERED;
  }

  usrsctp_sendv(connection.m_SctpSocket, data, length, nullptr, 0, &spa, sizeof(spa), SCTP_SENDV_SPA, 0);
}
