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
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "driver/rmt_tx.h"

#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "pcap_usb.h"

#define TARGET_IP   "192.168.4.1" // Địa chỉ IP của Node B (SoftAP)
#define TARGET_PORT 8888          // Cổng UDP nhận dữ liệu trên Node B
#define LED_GPIO    8             // Chân GPIO điều khiển LED RGB trên ESP32-C6

// Con trỏ lưu giữ hàm gửi dữ liệu tầng Data Link (L2) gốc của lwIP
static netif_linkoutput_fn s_orig_linkoutput = NULL;

// Hàm bật sáng tĩnh đèn LED RGB phân biệt phần cứng
static void set_led_color(uint8_t r, uint8_t g, uint8_t b) {
    rmt_channel_handle_t led_chan = NULL;
    rmt_tx_channel_config_t tx_chan_config = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .gpio_num = LED_GPIO,
        .mem_block_symbols = 64,
        .resolution_hz = 10000000, // Tần số 10MHz (1 tick = 0.1us)
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
    uint8_t grb[3] = { g, r, b }; // Chip WS2812 nhận thứ tự màu GRB
    rmt_transmit_config_t tx_config = { .loop_count = 0 }; // Phát 1 lần và giữ sáng tĩnh
    rmt_transmit(led_chan, led_encoder, grb, sizeof(grb), &tx_config);
    rmt_tx_wait_all_done(led_chan, portMAX_DELAY);

    // Giải phóng tài nguyên RMT ngay sau khi bật đèn xong để không chiếm RAM
    rmt_disable(led_chan);
    rmt_del_encoder(led_encoder);
    rmt_del_channel(led_chan);
}

// In-node Hook chiều gửi (TX): Chặn gói tin tại ranh giới lwIP và Wi-Fi Driver
static err_t hooked_linkoutput(struct netif *netif, struct pbuf *p) {
    if (p) {
        uint8_t buffer[1514]; // Kích thước tối đa của 1 khung Ethernet II
        // Gom các mảnh dữ liệu pbuf rời rạc trong RAM thành 1 mảng liên tục
        uint16_t copied = pbuf_copy_partial(p, buffer, sizeof(buffer), 0);
        if (copied > 0) {
            // Nhân bản khung Ethernet II gửi qua USB lên PC cho Wireshark
            pcap_usb_send_raw(buffer, copied);
        }
    }
    // Gọi lại hàm gửi gốc để gói tin tiếp tục được truyền ra sóng Wi-Fi
    return s_orig_linkoutput(netif, p);
}

// Tác vụ giả lập cảm biến gửi dữ liệu UDP định kỳ mỗi 1 giây
static void sensor_task(void *pvParameters) {
    vTaskDelay(pdMS_TO_TICKS(4000)); // Đợi 4 giây cho Wi-Fi kết nối và nhận IP xong

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP); // Tạo Socket UDP IPv4
    struct sockaddr_in dest_addr = {
        .sin_addr.s_addr = inet_addr(TARGET_IP), // Gán IP đích 192.168.4.1
        .sin_family = AF_INET,
        .sin_port = htons(TARGET_PORT),          // Gán cổng đích 8888
    };

    uint32_t seq = 0;   // Biến đếm số thứ tự gói tin
    char payload[128];  // Bộ đệm chứa chuỗi JSON

    while (1) {
        seq++; // Tăng số thứ tự bản tin
        float temp = 25.0f + (esp_random() % 100) / 10.0f; // Sinh nhiệt độ ngẫu nhiên 25.0 - 34.9
        int64_t send_time = esp_timer_get_time();          // Lấy thời gian hệ thống (micro giây)
        snprintf(payload, sizeof(payload), "{\"seq\":%lu,\"temp\":%.1f,\"t_us\":%lld}", (unsigned long)seq, temp, send_time);

        // Gửi gói tin UDP xuống ngăn xếp mạng
        sendto(sock, payload, strlen(payload), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        vTaskDelay(pdMS_TO_TICKS(1000)); // Nghỉ đúng 1 giây rồi lặp lại
    }
}

// Tác vụ giám sát tài nguyên RAM phục vụ Test 2 (Overhead)
static void benchmark_task(void *pvParameters) {
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(5000)); // Kiểm tra mỗi 5 giây
        uint32_t free_heap = esp_get_free_heap_size();         // RAM trống hiện tại
        uint32_t min_heap = esp_get_minimum_free_heap_size();  // RAM trống thấp nhất từng đạt
        (void)free_heap;
        (void)min_heap;
    }
}

void app_main(void) {
    set_led_color(30, 0, 0); // Bật đèn màu ĐỎ để nhận diện Node A

    nvs_flash_init();                // Khởi tạo bộ nhớ NVS lưu thông số Wi-Fi
    esp_netif_init();                // Khởi tạo lớp giao diện mạng TCP/IP
    esp_event_loop_create_default(); // Tạo vòng lặp sự kiện hệ thống

    // Khởi tạo USB PCAP với chuẩn khung Ethernet II (LinkType = 1)
    pcap_usb_init(PCAP_LINKTYPE_ETHERNET);

    // Khởi tạo giao diện Wi-Fi Station (máy khách)
    esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = "ESP32_Testbed", // Tên mạng Wi-Fi của Node B
            .password = "12345678",  // Mật khẩu kết nối
            .channel = 1             // Khóa Kênh 1 đồng bộ với toàn hệ thống
        },
    };
    esp_wifi_set_mode(WIFI_MODE_STA);              // Đặt chế độ Station
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config); // Nạp cấu hình Wi-Fi
    esp_wifi_start();                              // Bật bộ thu phát Wi-Fi
    esp_wifi_connect();                            // Kết nối vào Node B

    // Cài cắm In-node Hook vào con trỏ linkoutput của cấu trúc netif (lwIP)
    struct netif *lwip_netif = (struct netif *)esp_netif_get_netif_impl(sta_netif);
    if (lwip_netif) {
        s_orig_linkoutput = lwip_netif->linkoutput; // Lưu hàm gửi gốc
        lwip_netif->linkoutput = hooked_linkoutput; // Tráo sang hàm Hook TX
    }

    // Khởi tạo 2 tác vụ chạy song song trên FreeRTOS
    xTaskCreate(sensor_task, "sensor_task", 4096, NULL, 5, NULL);
    xTaskCreate(benchmark_task, "benchmark_task", 2048, NULL, 1, NULL);
}