cmake_minimum_required(VERSION 3.0)

set(CMAKE_CXX_STANDARD 14)

option(WEB "Emscripten Build" OFF)

include(EmscriptenBuild.cmake)

include_directories(.)
if(WEB)
  set(CMAKE_EXECUTABLE_SUFFIX ".html")
  set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS}")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --post-js ${PROJECT_SOURCE_DIR}/StormWebrtcClientAPI/WebRTC.js")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s EXPORTED_FUNCTIONS=\"['_main','_HandleStormWebrtcConnect','_HandleStormWebrtcMessage','_HandleStormWebrtcDisconnect']\"")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s TOTAL_MEMORY=134217728")

  add_subdirectory(StormWebrtcClientAPI)
  add_executable(StormWebrtcClientTest StormWebrtcClientTest/Main.cpp)

  target_link_libraries(StormWebrtcClientTest StormWebrtc)
  target_link_libraries(StormWebrtcClientTest StormWebrtcClient)
  
else()
  
  add_subdirectory(StormWebrtc)
  add_subdirectory(StormWebrtcServerAPI)
  add_subdirectory(StormWebrtcClientAPI)
  
  add_subdirectory(External/usrsctplib)
  add_subdirectory(External/mbedtls)

  add_subdirectory(External/asio)
  
  add_executable(StormWebrtcClientTest StormWebrtcClientTest/Main.cpp)
  target_link_libraries(StormWebrtcClientTest usrsctp-static)
  target_link_libraries(StormWebrtcClientTest mbedtls)
  target_link_libraries(StormWebrtcClientTest StormWebrtc)
  target_link_libraries(StormWebrtcClientTest StormWebrtcClientAPI)
  
  add_executable(StormWebrtcServerTest StormWebrtcTest/Main.cpp)
  target_link_libraries(StormWebrtcServerTest usrsctp-static)
  target_link_libraries(StormWebrtcServerTest mbedtls)
  target_link_libraries(StormWebrtcServerTest StormWebrtc)
  target_link_libraries(StormWebrtcServerTest StormWebrtcServerAPI)

endif()
