# Since ESP-IDF 5.3 the I2S driver is a component of its own; from 6.0 "driver" no longer pulls it in
if(IDF_VERSION_MAJOR GREATER_EQUAL 6 OR (IDF_VERSION_MAJOR EQUAL 5 AND IDF_VERSION_MINOR GREATER_EQUAL 3))
    set(i2s_component esp_driver_i2s)
else()
    set(i2s_component driver)
endif()

idf_component_register(SRCS "main.cpp"
                       REQUIRES ${i2s_component} esp_wifi esp_netif nvs_flash protocol_examples_common)
