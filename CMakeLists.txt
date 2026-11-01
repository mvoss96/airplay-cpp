# airplay-cpp: AirPlay 1 (RAOP) audio receiver. Works for generic CMake, ESP-IDF and Zephyr (see zephyr/).
#
#   add_subdirectory(airplay-cpp)
#   target_link_libraries(<your_target> PRIVATE airplay)
#
# ESP-IDF: this directory also doubles as a component.
cmake_minimum_required(VERSION 3.16)

set(AIRPLAY_SOURCES
    src/airplay_alac.cpp
    src/airplay_crypto_mbedtls.cpp
    src/airplay_dacp.cpp
    src/airplay_fairplay.cpp
    src/airplay_hap_crypto.cpp
    src/airplay_key.cpp
    src/airplay_log.cpp
    src/airplay_plist.cpp
    src/airplay_receiver.cpp
    src/airplay_receiver_ap2.cpp
    src/airplay_socket_runner.cpp
    src/airplay_srp.cpp
    src/airplay_tlv8.cpp
    src/airplay_util.cpp
)

if(DEFINED ESP_PLATFORM)
    idf_component_register(SRCS ${AIRPLAY_SOURCES}
                           INCLUDE_DIRS src
                           REQUIRES mbedtls lwip esp_timer esp_hw_support)
    return()
endif()

project(airplay_cpp CXX)

add_library(airplay STATIC ${AIRPLAY_SOURCES})
target_include_directories(airplay PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_features(airplay PUBLIC cxx_std_17)
add_library(airplay::airplay ALIAS airplay)

# The mbedTLS backend is built when mbedTLS 2.28, 3.x or 4.x is found; otherwise bring your own airplay::Crypto.
# mbedTLS 4 keeps its crypto in TF-PSA-Crypto (libtfpsacrypto).
find_path(AIRPLAY_MBEDTLS_INCLUDE mbedtls/version.h)
find_library(AIRPLAY_MBEDCRYPTO NAMES tfpsacrypto mbedcrypto)
if(AIRPLAY_MBEDTLS_INCLUDE AND AIRPLAY_MBEDCRYPTO)
    target_include_directories(airplay PUBLIC ${AIRPLAY_MBEDTLS_INCLUDE})
    target_link_libraries(airplay PUBLIC ${AIRPLAY_MBEDCRYPTO})
else()
    message(STATUS "airplay: mbedcrypto not found - MbedtlsCrypto is not built")
    target_compile_definitions(airplay PUBLIC AIRPLAY_NO_MBEDTLS)
endif()

# Host tests and examples: cmake -DAIRPLAY_BUILD_TESTS=ON ..
option(AIRPLAY_BUILD_TESTS "Build host tests" OFF)
option(AIRPLAY_BUILD_EXAMPLES "Build host examples" OFF)
set(AIRPLAY_WARNINGS -fno-exceptions -fno-rtti -Wall -Wextra)

if(AIRPLAY_BUILD_TESTS)
    enable_testing()
    target_compile_options(airplay PRIVATE ${AIRPLAY_WARNINGS})
    foreach(t IN ITEMS test_util test_alac test_sync test_hap)
        add_executable(${t} tests/${t}.cpp)
        target_link_libraries(${t} PRIVATE airplay)
        target_compile_options(${t} PRIVATE ${AIRPLAY_WARNINGS})
    endforeach()
    add_test(NAME test_util COMMAND test_util)
    add_test(NAME test_alac COMMAND test_alac ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors)
    add_test(NAME test_sync COMMAND test_sync --long)
    add_test(NAME test_hap COMMAND test_hap)
    if(AIRPLAY_MBEDCRYPTO)
        add_executable(test_session tests/test_session.cpp)
        target_link_libraries(test_session PRIVATE airplay)
        target_compile_options(test_session PRIVATE ${AIRPLAY_WARNINGS})
        add_test(NAME test_session COMMAND test_session)
    endif()
endif()

if(AIRPLAY_BUILD_EXAMPLES AND AIRPLAY_MBEDCRYPTO)
    add_executable(airplay_receiver examples/posix/main.cpp)
    target_link_libraries(airplay_receiver PRIVATE airplay)
    target_compile_options(airplay_receiver PRIVATE ${AIRPLAY_WARNINGS})
endif()
