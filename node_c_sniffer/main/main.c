#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "driver/rmt_tx.h"
#include "pcap_usb.h"

#define LED_GPIO 8 // Chân GPIO điều khiển LED RGB trên ESP32-C6

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

// Hàm ngắt tự động chạy mỗi khi ăng-ten bắt được bất kỳ gói sóng 802.11 nào
static void wifi_promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf; // Ép kiểu về gói tin Promiscuous
    uint32_t len = pkt->rx_ctrl.sig_len; // Lấy tổng độ dài khung vô tuyến thu được
    if (len > 4) len -= 4; // Cắt bỏ 4 byte mã kiểm lỗi CRC/FCS ở cuối khung để Wireshark đọc chuẩn
    pcap_usb_send_raw(pkt->payload, len); // Bắn thẳng khung Raw 802.11 qua USB lên PC
}

void app_main(void) {
    set_led_color(25, 25, 25); // Bật đèn màu TRẮNG để nhận diện Node C

    nvs_flash_init();                // Khởi tạo bộ nhớ NVS
    esp_netif_init();                // Khởi tạo lớp giao diện mạng
    esp_event_loop_create_default(); // Tạo vòng lặp sự kiện hệ thống

    // Khởi tạo USB PCAP với chuẩn khung Raw IEEE 802.11 (LinkType = 105)
    pcap_usb_init(PCAP_LINKTYPE_802_11);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_NULL); // Không làm Station hay AP (đứng ngoài mạng hoàn toàn)
    esp_wifi_start();                  // Bật bộ thu phát vô tuyến

    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);         // Khóa cứng tần số thu tại Kênh 1 (2412 MHz)
    esp_wifi_set_promiscuous_rx_cb(wifi_promiscuous_rx_cb); // Đăng ký hàm nhận gói tin vô tuyến
    esp_wifi_set_promiscuous(true);                         // Bật chế độ nghe lén toàn dải (Promiscuous Mode)
}