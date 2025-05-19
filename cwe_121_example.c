#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// CWE-121: Stack-based Buffer Overflow
// Based on real-world vulnerability in network protocol handling
// This example simulates a network packet processing function
// that is vulnerable to buffer overflow

#define MAX_PACKET_SIZE 1024
#define HEADER_SIZE 8

struct packet_header {
    uint16_t type;
    uint16_t length;
    uint32_t sequence;
};

void process_network_packet(const char* packet_data, size_t data_len) {
    char buffer[256];  // Fixed-size buffer for packet processing
    struct packet_header* header = (struct packet_header*)packet_data;
    
    // Vulnerable: No validation of packet length before copying
    // This could lead to buffer overflow if data_len is larger than buffer size
    memcpy(buffer, packet_data + HEADER_SIZE, data_len - HEADER_SIZE);
    
    // Process the packet
    printf("Processing packet type: %d, length: %d\n", 
           header->type, header->length);
    printf("Packet data: %s\n", buffer);
}

int main() {
    // Normal usage with small packet
    char normal_packet[] = "TYPE\x00\x01LEN\x00\x0A\x00\x00\x00\x01Hello World";
    process_network_packet(normal_packet, sizeof(normal_packet));
    
    // Malicious packet that could cause buffer overflow
    char* malicious_packet = (char*)malloc(MAX_PACKET_SIZE);
    if (malicious_packet) {
        // Create a packet with large length field
        struct packet_header* header = (struct packet_header*)malicious_packet;
        header->type = 1;
        header->length = MAX_PACKET_SIZE;  // Much larger than buffer size
        header->sequence = 1;
        
        // Fill the rest with 'A's to demonstrate overflow
        memset(malicious_packet + HEADER_SIZE, 'A', MAX_PACKET_SIZE - HEADER_SIZE);
        
        // This will cause a buffer overflow
        process_network_packet(malicious_packet, MAX_PACKET_SIZE);
        
        free(malicious_packet);
    }
    
    return 0;
} 