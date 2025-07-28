idf_component_register(
    SRCS "wsl_bypasser.c"
    INCLUDE_DIRS "interface"
    REQUIRES "esp_wifi wifi_controller" "esp_timer" "mbedtls" "driver"
)
target_link_libraries(${COMPONENT_LIB} -Wl,-zmuldefs)