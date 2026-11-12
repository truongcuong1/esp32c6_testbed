#pragma once
#include <stdint.h>
#include <stddef.h>

#define PCAP_LINKTYPE_ETHERNET  1    // Khung Ethernet II (Node A, B)
#define PCAP_LINKTYPE_802_11    105  // Khung Raw 802.11 MAC (Node C)

void pcap_usb_init(uint32_t link_type);
void pcap_usb_send_raw(const uint8_t *payload, uint32_t length);