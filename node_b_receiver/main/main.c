#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "driver/rmt_tx.h"

#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "pcap_usb.h"

#define LISTEN_PORT 8888 // Cổng UDP mở lắng nghe dữ liệu từ Node A
#define LED_GPIO    8    // Chân GPIO điều khiển LED RGB trên ESP32-C6

// Con trỏ lưu giữ hàm nhận dữ liệu tầng Data Link (L2) gốc của lwIP
static netif_input_fn s_orig_input = NULL;

// Hàm bật sáng tĩnh đèn LED RGB phân biệt phần cứng
static void set_led_color(uint8_t r, uint8_t g, uint8_t b) {
    rmt_channel_handle_t led_chan = NULL;
    rmt_tx_channel_config_t tx_chan_config = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .gpio_num = LED_GPIO,
        .mem_block_symbols = 64,
        .resolution_hz = 10000000, // Tần số 10MHz
        .trans_queue_depth = 4,
    };
    rmt_new_tx_channel(&tx_chan_config, &led_chan);

    rmt_bytes_encoder_config_t bytes_encoder_config = {
        .bit0 = { .level0 = 1, .duration0 = 3, .level1 = 0, .duration1 = 9 },
        .bit1 = { .level0 = 1, .duration0 = 9, .level1 = 0, .duration1 = 3 },
        .flags.msb_first = 1
    };
    rmt_encoder_handle_t led_encoder = NULL;
    rmt_new_bytes_encoder(&bytes_encoder_config, &led_encoder);

    rmt_enable(led_chan);
    uint8_t grb[3] = { g, r, b }; // Thứ tự màu GRB của chip WS2812
    rmt_transmit_config_t tx_config = { .loop_count = 0 }; // Sáng tĩnh
    rmt_transmit(led_chan, led_encoder, grb, sizeof(grb), &tx_config);
    rmt_tx_wait_all_done(led_chan, portMAX_DELAY);

    rmt_disable(led_chan);
    rmt_del_encoder(led_encoder);
    rmt_del_channel(led_chan);
}

// In-node Hook chiều nhận (RX): Chặn ngay khi Wi-Fi driver vừa đưa gói tin lên lwIP
static err_t hooked_input(struct pbuf *p, struct netif *netif) {
    if (p) {
        uint8_t buffer[1514]; // Mảng tạm chứa khung Ethernet II
        uint16_t copied = pbuf_copy_partial(p, buffer, sizeof(buffer), 0);
        if (copied > 0) {
            // Nhân bản khung Ethernet II nhận được gửi qua USB lên PC cho Wireshark
            pcap_usb_send_raw(buffer, copied);
        }
    }
    // Chuyển tiếp gói tin gốc lên tầng IP -> UDP -> Socket
    return s_orig_input(p, netif);
}

// Tác vụ máy chủ UDP hứng dữ liệu từ Node A
static void udp_server_task(void *pvParameters) {
    char rx_buffer[128];
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP); // Tạo Socket UDP
    struct sockaddr_in server_addr = {
        .sin_addr.s_addr = htonl(INADDR_ANY), // Lắng nghe trên mọi IP nội bộ
        .sin_family = AF_INET,
        .sin_port = htons(LISTEN_PORT),       // Gắn vào cổng 8888
    };
    bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    while (1) {
        struct sockaddr_in source_addr;
        socklen_t socklen = sizeof(source_addr);
        // Nhận dữ liệu từ tầng ứng dụng
        int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer) - 1, 0, (struct sockaddr *)&source_addr, &socklen);
        if (len > 0) {
            rx_buffer[len] = 0; // Đóng chuỗi ký tự an toàn
        }
    }
}

void app_main(void) {
    set_led_color(0, 30, 0); // Bật đèn màu XANH LÁ để nhận diện Node B

    nvs_flash_init();                // Khởi tạo bộ nhớ NVS
    esp_netif_init();                // Khởi tạo lớp giao diện mạng TCP/IP
    esp_event_loop_create_default(); // Tạo vòng lặp sự kiện hệ thống

    // Khởi tạo USB PCAP với chuẩn khung Ethernet II (LinkType = 1)
    pcap_usb_init(PCAP_LINKTYPE_ETHERNET);

    // Khởi tạo giao diện Wi-Fi SoftAP (điểm phát sóng, IP mặc định 192.168.4.1)
    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    wifi_config_t wifi_config = {
        .ap = {
            .ssid = "ESP32_Testbed",         // Phát tên Wi-Fi ESP32_Testbed
            .ssid_len = strlen("ESP32_Testbed"),
            .password = "12345678",          // Mật khẩu mạng
            .max_connection = 4,             // Tối đa 4 thiết bị kết nối cùng lúc
            .authmode = WIFI_AUTH_WPA2_PSK,  // Chuẩn bảo mật WPA2
            .channel = 1                     // Phát cố định ở Kênh 1
        },
    };
    esp_wifi_set_mode(WIFI_MODE_AP);              // Đặt chip chạy chế độ Access Point
    esp_wifi_set_config(WIFI_IF_AP, &wifi_config); // Nạp cấu hình SoftAP
    esp_wifi_start();                             // Bắt đầu phát sóng Wi-Fi

    // Cài cắm In-node Hook vào con trỏ input của cấu trúc netif (lwIP)
    struct netif *lwip_netif = (struct netif *)esp_netif_get_netif_impl(ap_netif);
    if (lwip_netif) {
        s_orig_input = lwip_netif->input; // Lưu hàm nhận L2 gốc
        lwip_netif->input = hooked_input; // Tráo sang hàm Hook RX
    }

    // Khởi tạo tác vụ lắng nghe gói tin UDP
    xTaskCreate(udp_server_task, "udp_server", 4096, NULL, 5, NULL);
}