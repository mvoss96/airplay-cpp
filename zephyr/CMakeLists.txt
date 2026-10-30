# Zephyr module integration for airplay-cpp
if(CONFIG_AIRPLAY_CPP)
  set(AIRPLAY_DIR ${CMAKE_CURRENT_LIST_DIR}/..)
  zephyr_library()
  zephyr_library_sources(
    ${AIRPLAY_DIR}/src/airplay_alac.cpp
    ${AIRPLAY_DIR}/src/airplay_crypto_mbedtls.cpp
    ${AIRPLAY_DIR}/src/airplay_dacp.cpp
    ${AIRPLAY_DIR}/src/airplay_key.cpp
    ${AIRPLAY_DIR}/src/airplay_log.cpp
    ${AIRPLAY_DIR}/src/airplay_receiver.cpp
    ${AIRPLAY_DIR}/src/airplay_socket_runner.cpp
    ${AIRPLAY_DIR}/src/airplay_util.cpp
  )
  zephyr_include_directories(${AIRPLAY_DIR}/src)
  if(CONFIG_MBEDTLS)
    zephyr_library_link_libraries(mbedTLS)
  else()
    zephyr_compile_definitions(AIRPLAY_NO_MBEDTLS)
  endif()
  if(NOT CONFIG_POSIX_API)
    zephyr_compile_definitions(AIRPLAY_NO_SOCKETS)
  endif()
endif()
