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
    src/airplay_key.cpp
    src/airplay_log.cpp
    src/airplay_receiver.cpp
    src/airplay_socket_runner.cpp
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

# The mbedTLS backend is built when libmbedcrypto is found; otherwise bring your own airplay::Crypto.
find_path(AIRPLAY_MBEDTLS_INCLUDE mbedtls/version.h)
find_library(AIRPLAY_MBEDCRYPTO mbedcrypto)
if(AIRPLAY_MBEDTLS_INCLUDE)
    # mbedTLS 4 offers only the PSA crypto API, which the backend does not use yet
    file(STRINGS ${AIRPLAY_MBEDTLS_INCLUDE}/mbedtls/version.h AIRPLAY_MBEDTLS_MAJOR
         REGEX "^#define MBEDTLS_VERSION_MAJOR +[0-9]+")
    if(NOT AIRPLAY_MBEDTLS_MAJOR AND EXISTS ${AIRPLAY_MBEDTLS_INCLUDE}/mbedtls/build_info.h)
        file(STRINGS ${AIRPLAY_MBEDTLS_INCLUDE}/mbedtls/build_info.h AIRPLAY_MBEDTLS_MAJOR
             REGEX "^#define MBEDTLS_VERSION_MAJOR +[0-9]+")
    endif()
    string(REGEX MATCH "[0-9]+$" AIRPLAY_MBEDTLS_MAJOR "${AIRPLAY_MBEDTLS_MAJOR}")
    if(AIRPLAY_MBEDTLS_MAJOR AND AIRPLAY_MBEDTLS_MAJOR GREATER_EQUAL 4)
        message(WARNING "airplay: mbedTLS ${AIRPLAY_MBEDTLS_MAJOR} is not supported yet, use mbedTLS 2.28 or 3.x "
                        "(macOS: brew install mbedtls@3 and -DCMAKE_PREFIX_PATH=$(brew --prefix mbedtls@3))")
        unset(AIRPLAY_MBEDCRYPTO CACHE)
        set(AIRPLAY_MBEDCRYPTO "")
    endif()
endif()
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
    foreach(t IN ITEMS test_util test_alac test_sync)
        add_executable(${t} tests/${t}.cpp)
        target_link_libraries(${t} PRIVATE airplay)
        target_compile_options(${t} PRIVATE ${AIRPLAY_WARNINGS})
    endforeach()
    add_test(NAME test_util COMMAND test_util)
    add_test(NAME test_alac COMMAND test_alac ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors)
    add_test(NAME test_sync COMMAND test_sync --long)
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
