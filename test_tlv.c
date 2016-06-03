//
// Created by jared on 6/2/16.
//

#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>

#include "tlv.h"
#include "debug.h"

#define HEADER "******************************************************"
#define PRINT_HEADER(M, ...) printf("\n\n" HEADER "\n\t" M "\n" HEADER "\n\n", ##__VA_ARGS__)

const char packet_path[] = "packet";
int main()
{
    FILE *fd = 0;
    uint8_t *packet = NULL;
    lldp_tlv_list *tlv_list = NULL;
    lldp_tlv_list *current = NULL;

    log_info("Starting up...");
    fd = fopen(packet_path, "rb");
    packet = (uint8_t *) malloc(IP_MAXPACKET * sizeof(uint8_t));
    fread(packet, sizeof(uint8_t), IP_MAXPACKET, fd);

    tlv_list = tlv_list_create();
    current = tlv_list;
    PRINT_HEADER("Parsing packet");
    parse_lldp_packet(packet, tlv_list);

    PRINT_HEADER("Printing TLVs");
    while (current->next != NULL) {
        print_tlv(current->tlv);
        current = current->next;
    }
}