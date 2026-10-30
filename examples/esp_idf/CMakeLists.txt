# AirPlay speaker on an ESP32 with an I2S amplifier or DAC (e.g. MAX98357A, PCM5102A).
# Wi-Fi credentials: idf.py menuconfig -> Example Connection Configuration.
cmake_minimum_required(VERSION 3.16)
set(EXTRA_COMPONENT_DIRS $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(airplay_idf_example)
