#include "pcap_usb.h"
#include "driver/usb_serial_jtag.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"

typedef struct __attribute__((packed)) {
    uint32_t magic_number;   // 0xa1b2c3d4
    uint16_t version_major;  // 2
    uint16_t version_minor;  // 4
    int32_t  thiszone;       // 0
    uint32_t sigfigs;        // 0
    uint32_t snaplen;        // 65535
    uint32_t network;        // LinkType
} pcap_global_header_t;

typedef struct __attribute__((packed)) {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_packet_header_t;

void pcap_usb_init(uint32_t link_type) {
    usb_serial_jtag_driver_config_t config = {
        .tx_buffer_size = 4096,
        .rx_buffer_size = 512,
    };
    usb_serial_jtag_driver_install(&config);

    pcap_global_header_t gh = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = link_type
    };
    usb_serial_jtag_write_bytes((const char *)&gh, sizeof(gh), portMAX_DELAY);
}

void pcap_usb_send_raw(const uint8_t *payload, uint32_t length) {
    if (!payload || length == 0) return;

    int64_t now_us = esp_timer_get_time();
    pcap_packet_header_t ph = {
        .ts_sec = (uint32_t)(now_us / 1000000ULL),
        .ts_usec = (uint32_t)(now_us % 1000000ULL),
        .incl_len = length,
        .orig_len = length
    };

    usb_serial_jtag_write_bytes((const char *)&ph, sizeof(ph), pdMS_TO_TICKS(10));
    usb_serial_jtag_write_bytes((const char *)payload, length, pdMS_TO_TICKS(20));
}