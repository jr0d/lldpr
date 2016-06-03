//
// Created by jared on 6/2/16.
//

#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>

#include "tlv.h"
#include "debug.h"
#include "lldpr.h"

const char packet_path[] = "packet";
int main()
{
    FILE *fd = 0;
    uint8_t *packet = NULL;
    size_t packet_len = 0;
    lldp_tlv_list *tlv_list = NULL;
    lldp_tlv_list *current = NULL;

    log_info("Starting up...");

    if ((fd = fopen(packet_path, "rb")) == NULL) {
        log_err("Problem opening: %s", packet_path);
        exit(EXIT_FAILURE);
    }

    packet = (uint8_t *) malloc(IP_MAXPACKET * sizeof(uint8_t));
    packet_len = fread(packet, sizeof(uint8_t), IP_MAXPACKET, fd);

    if (packet_len < sizeof(ethernet_header)) {
        log_err("Packet is not large enough, need at least %zu bytes, only read: %lu", sizeof(ethernet_header), packet_len);
        exit(EXIT_FAILURE);
    }
    log_info("Read in %lu bytes from %s\n", packet_len, packet_path);
    tlv_list = tlv_list_create();

    PRINT_HEADER("PARSING PACKET");
    parse_lldp_packet(packet, tlv_list);

    PRINT_HEADER("PRINTING TLVs");

    current = tlv_list;

    if (current->tlv == NULL) {
        log_info("No TLVs print");
        exit(EXIT_SUCCESS);
    }

    while (current->next != NULL) {
        print_tlv(current->tlv);
        current = current->next;
    }
    print_tlv(current->tlv);

    PRINT_HEADER("DESTROYING LIST");
    tlv_list_destroy(tlv_list);
    PRINT_HEADER("DONE");
    return EXIT_SUCCESS;
}