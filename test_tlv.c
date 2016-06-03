//
// Created by jared on 6/2/16.
//

#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>

#include "tlv.h"

const char packet_path[] = "packet";
int main()
{
    FILE *fd = 0;
    uint8_t *packet = NULL;
    lldp_tlv_list *tlv_list = NULL;
    lldp_tlv_list *current = NULL;

    fd = fopen(packet_path, "rb");
    packet = (uint8_t *) malloc(IP_MAXPACKET * sizeof(uint8_t));
    fread(packet, sizeof(uint8_t), IP_MAXPACKET, fd);

    tlv_list = tlv_list_create();
    current = tlv_list;
    parse_lldp_packet(packet, tlv_list);

    while (current->next != NULL) {
        print_tlv(current->tlv);
        current = current->next;
    }
}