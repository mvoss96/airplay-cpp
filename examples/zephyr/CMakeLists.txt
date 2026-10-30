cmake_minimum_required(VERSION 3.20)
# airplay-cpp as a Zephyr module (in your west manifest, add the repository as a project instead)
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(airplay_zephyr_example)

target_sources(app PRIVATE src/main.cpp)
