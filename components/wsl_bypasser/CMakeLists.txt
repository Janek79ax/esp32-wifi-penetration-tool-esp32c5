idf_component_register(
    SRCS "wsl_bypasser.c"
    INCLUDE_DIRS "interface"
    REQUIRES "esp_wifi wifi_controller"
)
target_link_libraries(${COMPONENT_LIB} -Wl,-zmuldefs)