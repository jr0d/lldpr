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

#include <net/ethernet.h>


#include "lldpr.h"

uint8_t * fetch_lldp_packet() {
    int sock = 0;
    int cnt = 0;
    ssize_t packet_len = 0;

    char dest_address[MAC_STRING_LEN];
    char src_address[MAC_STRING_LEN];

    uint8_t *packet = NULL;

    ethernet_header *eh = NULL;
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

    printf ("LLDP packet received! Ethernet type code: 0x%04x\n", htons(eh->type));
    printf ("\nEthernet frame header:\n");

    mac_address_fmt(eh->dest, dest_address);
    mac_address_fmt(eh->src, src_address);

    printf ("Destination MAC (this node): %s\n", dest_address);
    printf ("Source MAC: %s\n", src_address);

    printf("Total packets: %d\n\n", cnt);
    return packet;
}

void mac_address_fmt(uint8_t *addr, char *buff) {
    snprintf(buff, MAC_STRING_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}
