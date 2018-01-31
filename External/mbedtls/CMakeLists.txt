cmake_minimum_required(VERSION 3.0)

include_directories(. ../../. ../.././External)
set(CMAKE_CXX_STANDARD 14)

if (WEB)
  add_definitions(-D_WEB)
  include_directories(../.././External/Web)
  set(PLATFORM_SRC_mbedtls 
            )
elseif (MSVC)
  add_definitions(-D_WINDOWS)
  include_directories(../.././External/Windows)
  set(PLATFORM_SRC_mbedtls 
            )
elseif (IOS)
  add_definitions(-D_IOS)
  include_directories(../.././External/IOS)
  set(PLATFORM_SRC_mbedtls 
            )
elseif (APPLE)
  add_definitions(-D_MACOS)
  include_directories(/usr/include/freetype2)
  set(PLATFORM_SRC_mbedtls 
            )
elseif (ANDROID)
  add_definitions(-D_ANDROID)
  include_directories(../.././External/Android)
  set(PLATFORM_SRC_mbedtls 
            )
elseif (UNIX)
  add_definitions(-D_LINUX)
  include_directories(/usr/include/freetype2)
  set(PLATFORM_SRC_mbedtls 
            )
endif()

set(GENERIC_SRC_mbedtls 
            ./aes.c
            ./aesni.c
            ./arc4.c
            ./asn1parse.c
            ./asn1write.c
            ./base64.c
            ./bignum.c
            ./blowfish.c
            ./camellia.c
            ./ccm.c
            ./certs.c
            ./cipher.c
            ./cipher_wrap.c
            ./ctr_drbg.c
            ./debug.c
            ./des.c
            ./dhm.c
            ./ecdh.c
            ./ecdsa.c
            ./ecjpake.c
            ./ecp.c
            ./ecp_curves.c
            ./entropy.c
            ./entropy_poll.c
            ./error.c
            ./gcm.c
            ./havege.c
            ./hmac_drbg.c
            ./md.c
            ./md2.c
            ./md4.c
            ./md5.c
            ./md_wrap.c
            ./memory_buffer_alloc.c
            ./net.c
            ./oid.c
            ./padlock.c
            ./pem.c
            ./pk.c
            ./pkcs11.c
            ./pkcs12.c
            ./pkcs5.c
            ./pkparse.c
            ./pkwrite.c
            ./pk_wrap.c
            ./platform.c
            ./ripemd160.c
            ./rsa.c
            ./sha1.c
            ./sha256.c
            ./sha512.c
            ./ssl_cache.c
            ./ssl_ciphersuites.c
            ./ssl_cli.c
            ./ssl_cookie.c
            ./ssl_srv.c
            ./ssl_ticket.c
            ./ssl_tls.c
            ./threading.c
            ./timing.c
            ./version.c
            ./version_features.c
            ./x509.c
            ./x509write_crt.c
            ./x509write_csr.c
            ./x509_create.c
            ./x509_crl.c
            ./x509_crt.c
            ./x509_csr.c
            ./xtea.c
            )
add_library(mbedtls ${GENERIC_SRC_mbedtls} ${PLATFORM_SRC_mbedtls} )