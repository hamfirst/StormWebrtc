cmake_minimum_required(VERSION 3.0)

set(CMAKE_CXX_STANDARD 14)

include(EmscriptenBuild.cmake)

include_directories(.)

set(CMAKE_EXECUTABLE_SUFFIX ".html")
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --post-js ${PROJECT_SOURCE_DIR}/StormWebrtcClientAPI/WebRTC.js")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s EXPORTED_FUNCTIONS=\"['_main','_HandleStormWebrtcConnect','_HandleStormWebrtcMessage','_HandleStormWebrtcDisconnect']\"")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s TOTAL_MEMORY=134217728")

add_subdirectory(StormWebrtcClientAPI)
add_executable(StormWebrtcClientTest StormWebrtcClientTest/Main.cpp)

target_link_libraries(StormWebrtcClientTest StormWebrtcClient)
