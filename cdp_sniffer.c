#include <pcap.h> // Packet capture library
#include <stdio.h> // Standard I/O functions
#include <stdlib.h> // Standard library functions
#include <string.h> // String manipulation functions
#include <arpa/inet.h> // Functions for network byte order conversions

// CDP SNAP protocol ID
#define CDP_SNAP 0x2000 // Protocol ID for Cisco Discovery Protocol (CDP)

// Callback function to process each captured packet
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
    // Pointer to the Ethernet header
    const u_char *ethernet = packet;

    // Pointer to the payload (after Ethernet and SNAP headers)
    const u_char *payload = packet + 14 + 8; // Ethernet header (14 bytes) + SNAP header (8 bytes)

    // Check for CDP protocol ID in the SNAP header
    u_short protocol_id = ntohs(*(u_short *)(packet + 20)); // Extract protocol ID from SNAP header
    if (protocol_id != CDP_SNAP) return; // Ignore packets that are not CDP

    printf("=== CDP Packet Detected ===\n");

    // Skip CDP Header (version + TTL + checksum = 4 bytes)
    const u_char *tlv = payload + 4;

    // Loop through the CDP Type-Length-Value (TLV) fields
    while ((tlv - packet) < header->caplen) {
        uint16_t type = ntohs(*(uint16_t *)tlv); // Extract TLV type
        uint16_t length = ntohs(*(uint16_t *)(tlv + 2)); // Extract TLV length

        if (length < 4) break; // Ensure valid TLV length

        // Process TLV based on its type
        switch (type) {
            case 0x0001: // Device ID TLV
                printf("Device ID: %.*s\n", length - 4, tlv + 4); // Print Device ID
                break;
            case 0x0003: // Port ID TLV
                printf("Port ID: %.*s\n", length - 4, tlv + 4); // Print Port ID
                break;
            case 0x0005: // Platform TLV
                printf("Platform: %.*s\n", length - 4, tlv + 4); // Print Platform information
                break;
            default:
                break; // Ignore other TLV types
        }

        tlv += length; // Move to the next TLV
    }
}

int main() 
{
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer to store error messages
    pcap_if_t *alldevs, *dev; // Pointers to the list of devices and the selected device
    
    // Find all available network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf); // Print error message
        return 1;
    }

    dev = alldevs; // Select the first device (can be modified to allow manual selection)

    // Open the selected device for live packet capture
    pcap_t *handle = pcap_open_live(dev->name, 65535, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf); // Print error message
        return 2;
    }

    printf("Listening on interface: %s\n", dev->name); // Print the selected interface

    // Compile and apply a filter for CDP packets (multicast MAC address 01:00:0c:cc:cc:cc)
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ether dst 01:00:0c:cc:cc:cc", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Failed to apply filter\n"); // Print error message
        return 3;
    }

    // Start capturing packets in a loop
    pcap_loop(handle, -1, packet_handler, NULL); // Process packets with the packet_handler callback

    // Clean up resources
    pcap_close(handle); // Close the packet capture handle
    pcap_freealldevs(alldevs); // Free the list of devices
    return 0;
}
