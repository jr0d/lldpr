/*  lldpr.c -- sniff for incoming LLDP on local interfaces
 * 
 *  Author: Jared Rodriguez < jared.rodriguez@rackspace.com >
 *  Copyright: 2016
 *  MOAR HEADER
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset()

#include <netinet/ip.h>       // IP_MAXPACKET (65535)
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()

#include "lldpr.h"


lldp_tlv_list * tlv_list_create() {
    return (lldp_tlv_list *) calloc(1, sizeof(lldp_tlv_list));
}

void tlv_list_push(lldp_tlv_list *head, TLV *tlv) {
    lldp_tlv_list *current = head;
    while (current->next != NULL) 
        current = current->next;

    current->next = tlv_list_create();
    current->next = tlv;
    current->next->next = NULL;
}

lldp_tlv_list parse_lldp_packet(uint8_t *packet, lldp_tlv_list *head) {
    /*
     * Iterate over TLVs. Expload TLVs and store them in a linked list. Validations should occur before calling this function
     */

    TLV *current_tlv;
    uint16_t *tlv_header = 0;
    uint16_t tlv_length = 0;
    uint16_t tlv_offset = 0;

    do {
        tlv_header = (uint16_t *) &packet[calc_offset(tlv_offset)]; 
        current_tlv (TLV *) calloc(1, sizeof(TLV));
        current_tlv->type = TLV_TYPE(htons(*tlv_header));
        current_tlv->length = TLV_LENGTH(htons(*tlv_header));

        if (current_tlv->length > 0) {
            current_tlv->data (uint8_t *) calloc(1, current_tlv->length);
            memcpy(tlv->data, (uint8_t *) &packet[cacl_offset(tlv_offset) + sizeof(*tlv_header)], current_tlv->length) 
        } else
            current_tlv->data = NULL;
   
        tlv_offset += sizeof(*tlv_header) + current_tlv->length;
        
        if (tlv_list->tlv == NULL)

    } while(current_tlv->type != 0);
}

/* MAIN */

int main()
{
    int sock = 0;
    int cnt = 0;
    
    size_t  packet_len = 0;

    uint8_t tlv_type = 0;
    uint8_t tlv_subtype = 0;
    uint8_t msap_address[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    uint8_t *packet = NULL;
    uint8_t *tlv_info_string = NULL;

    uint16_t *tlv_header = 0;
    uint16_t tlv_length = 0;
    uint16_t tlv_offset = 0;
    uint16_t msap_ttl = 0;

    char msap_mac_t1[MAC_STRING_LEN];
    char msap_mac_t2[MAC_STRING_LEN];
    char dest_address[MAC_STRING_LEN];
    char src_address[MAC_STRING_LEN];
    
    char *info_string = NULL;
    
    lldp_tlv_list *tlv_list = NULL;
    ethernet_header *eh = NULL;
    TLV *tlv = NULL;

    packet = (uint8_t *) malloc(IP_MAXPACKET * sizeof(uint8_t));
    
    if(packet == NULL) {
        perror("Could not allocate memory for packet buffer");
        exit(EXIT_FAILURE);
    }
    
    memset(packet, 0, IP_MAXPACKET * sizeof(uint8_t));

    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
        perror("socket() failed");
        exit (EXIT_FAILURE);
    }
    // setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "eno1", strlen("eno1") + 1);


    eh = (ethernet_header *) packet;
    // timer / timeout
    while(1) {
        packet_len = recv(sock, packet, IP_MAXPACKET, 0);

        if (packet_len < 0) {
            perror("Problem getting packet");
            exit(EXIT_FAILURE);
        }
        cnt++;
        if (eh->type == htons(ETH_P_LLDP))
            break;

        // if (htons(eh->type) != 0x0800)
        //    printf("Got packet, just not the right one: 0x%04x\n", htons(eh->type));

        memset(packet, 0, IP_MAXPACKET * sizeof(uint8_t));
    }

    close(sock);

    // Write debug packet
    
    FILE * fp;
    fp = fopen("/tmp/packet", "wb");
    fwrite(packet, 1, packet_len, fp);
    fclose(fp);

    // Done

    printf ("LLDP packet received! Ethernet type code: 0x%04x\n", htons(eh->type));
    printf ("\nEthernet frame header:\n");

    mac_address_fmt(eh->dest, dest_address);
    mac_address_fmt(eh->src, src_address);

    printf ("Destination MAC (this node): %s\n", dest_address);
    printf ("Source MAC: %s\n", src_address);

    printf("Total packets: %d\n\n", cnt);

    // BEGIN TLV loop
    
    do {
        tlv_header = (uint16_t * ) &packet[calc_offset(tlv_offset)];

        tlv_type = htons(*tlv_header) >> 9;
        tlv_length = htons(*tlv_header) & 0x01ff;

        tlv_info_string = (uint8_t *) &packet[calc_offset(tlv_offset) + sizeof(*tlv_header)];  // AKA sizeof(uint16_t) (2 bytes)

        tlv = (TLV *) calloc(1, sizeof(TLV));
        tlv->type = tlv_type;
        tlv->length = tlv_length;
        if(tlv_length > 0) {
            tlv->data = (uint8_t *) calloc(1, tlv_length);
            memcpy(tlv->data, tlv_info_string, tlv_length);
        }

        tlv_offset += sizeof(*tlv_header) + tlv_length;

        printf("TLV: %u\n", tlv->type);
        printf("TLV Length: %d\n", tlv->length);
        printf("TLV info string: ");

        switch (tlv->type) {
            case 0:
                printf("End of TLV\n");
                break;
            case 1:
                tlv_subtype = tlv->data[0];
                memcpy(&msap_address, tlv->data+1, tlv_length-1);
                mac_address_fmt(msap_address, msap_mac_t1);
                printf("SUBTYPE: %d - MSAP ADDRESS: %s\n", tlv_subtype, msap_mac_t1);
                break;
            case 2:
                tlv_subtype = tlv->data[0];
                if(tlv_subtype == 3) {
                    memcpy(&msap_address, tlv->data+1, tlv_length-1);
                    mac_address_fmt(msap_address, msap_mac_t2);
                    printf("SUBTYPE: %d - PORT ID MAC: %s\n", tlv_subtype, msap_mac_t2);
                    break;
                } else if(tlv_subtype == 5) {
                    info_string = (char *) calloc(1, tlv_length + 1);
                    strncpy(info_string, (const char *) tlv->data+1, tlv_length-1);
                    info_string[tlv_length] = '\0';
                    printf("SUBTYPE: %d - PORT ID INTERFACE %s\n", tlv_subtype, info_string);
                    free(info_string);
                    break;
                } else
                    printf("SUBTYPE: %d - SUBTYPE unhandled\n", tlv_subtype);
            case 3:
                msap_ttl = *(uint16_t *) &tlv->data[0];
                printf("TTL: %d : %04x\n", ntohs(msap_ttl), msap_ttl);
                break;
            default:
                printf("Type unhandled\n");
        }
        printf("TLV Offset: %d\n", tlv_offset);
        printf("\n");
    } while(tlv_type != 0);
}

void mac_address_fmt(uint8_t *addr, char *buff) {
    snprintf(buff, MAC_STRING_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}
