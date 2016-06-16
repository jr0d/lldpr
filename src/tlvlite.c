//
// Created by jared on 6/16/16.
//

#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>

#include "tlv.h"
#include "lldpr.h"

const time_t timeout = 120;

int main(int argc, char **argv)
{
    uint8_t *packet;
    lldp_tlv_list *tlv_list = NULL;
    TLV * port_id_tlv = NULL;
    TLV * system_name_tlv = NULL;
    char *info_string = NULL;

    char ifname[20] = "\0";
    char mac_address[MAC_STRING_LEN] = "\0";

    if (argc < 2) {
        fprintf(stderr, "Usage: lldplite <interface>\n");
        exit(3);
    }

    strncpy(ifname, argv[1], 20);

    packet = fetch_lldp_packet(ifname, timeout);

    tlv_list = tlv_list_create();

    parse_lldp_packet(packet, tlv_list);

    if ((port_id_tlv = get_tlv(tlv_list, TLV_PORT_ID)) == NULL) {
        fprintf(stderr, "Port ID TLV is missing\n");
        exit(2);
    }
    if ((system_name_tlv = get_tlv(tlv_list, TLV_SYSNAME)) == NULL) {
        fprintf(stderr, "System Name TLV is missing\n");
        exit(2);
    }

    info_string = (char *) calloc(1, system_name_tlv->length + 1);
    strncpy(info_string, (const char *) system_name_tlv->data, system_name_tlv->length);
    info_string[system_name_tlv->length] = '\0';
    printf("%s ", info_string);
    free(info_string);

    tlv_list_destroy(tlv_list);
    if (port_id_tlv->data[0] == 3) {
        printf("%s\n", mac_address_fmt(port_id_tlv->data+1, mac_address));
    } else if(port_id_tlv->data[0] == 5) {
        info_string = (char *) calloc(1, port_id_tlv->length + 1);
        strncpy(info_string, (const char *) port_id_tlv->data + 1, port_id_tlv->length - (size_t) 1);
        info_string[port_id_tlv->length] = '\0';
        printf("%s\n", info_string);
        free(info_string);
    } else {
        fprintf(stderr, "Port ID TLV is not subtype 3 or 5, but %u instead\n", port_id_tlv->data[0]);
        exit(2);
    }

    free(packet);
    return EXIT_SUCCESS;
}