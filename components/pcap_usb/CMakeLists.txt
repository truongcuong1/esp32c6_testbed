idf_component_register(
    SRCS "pcap_usb.c"
    INCLUDE_DIRS "include"
    REQUIRES driver esp_timer
)