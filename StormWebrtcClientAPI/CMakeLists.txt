cmake_minimum_required(VERSION 3.0)

include_directories(. ../. .././External)
set(CMAKE_CXX_STANDARD 14)

if (WEB)
  add_definitions(-D_WEB)
  include_directories(.././External/Web)
  set(PLATFORM_SRC_StormWebrtcClientAPI 
            )
elseif (MSVC)
  add_definitions(-D_WINDOWS)
  include_directories(.././External/Windows)
  set(PLATFORM_SRC_StormWebrtcClientAPI 
            )
elseif (APPLE)
  add_definitions(-D_MACOS)
  include_directories(/usr/include/freetype2)
  set(PLATFORM_SRC_StormWebrtcClientAPI 
            )
elseif (UNIX)
  add_definitions(-D_LINUX)
  include_directories(/usr/include/freetype2)
  set(PLATFORM_SRC_StormWebrtcClientAPI 
            )
endif()

add_definitions(-D__Userspace__)
add_definitions(-D__Userspace_os_${CMAKE_SYSTEM_NAME})
add_definitions(-D_GNU_SOURCE)
add_definitions(-DINET)
add_definitions(-DINET6)
add_definitions(-DSCTP_PROCESS_LEVEL_LOCKS)
add_definitions(-DSCTP_SIMPLE_ALLOCATOR)

set(GENERIC_SRC_StormWebrtcClientAPI 
            ./StormWebrtcClient.cpp
            ./StormWebrtcClientNative.cpp
            ./StormWebrtcClientWeb.cpp
            )
add_library(StormWebrtcClientAPI ${GENERIC_SRC_StormWebrtcClientAPI} ${PLATFORM_SRC_StormWebrtcClientAPI} )