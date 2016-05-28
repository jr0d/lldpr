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


#define ETH_P_ALL 0x0003
#define ETH_P_LLDP 0x88CC
#define MAC_STRING_LEN 18     // FF:FF:FF:FF:FF:FF\0

typedef struct {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
} ethernet_header;

typedef struct {
    uint8_t type;
    uint16_t length;
    uint8_t *data;
} lldp_tlv;

/* Prototypes */

void mac_address_fmt(uint8_t *addr, char *buff);

/* MAIN */

int main()
{
    int sock = 0;
    int status = 0;
    int cnt = 0;
    
    size_t  packet_len = 0;

    uint8_t tlv_type = 0;
    uint8_t *packet = NULL;
    uint8_t *tlv_info_string = NULL
    uint16_t *tlv_header = 0;
    uint16_t tlv_length = 0;
    uint16_t tlv_offset = 0;
    
    char dest_address[MAC_STRING_LEN] = NULL;
    char  src_address[MAC_STRING_LEN] = NULL;
    
    ethernet_header *eh = NULL;
    lldp_tlv *tlv = NULL;

    packet = (uint8_t *) malloc(IP_MAXPACKET * sizeof(uint8_t));
    
    if(packet == NULL) {
        perror("Could not allocate memory for packet buffer");
        exit(EXIT_FAILURE);
    }
    
    memset(packet, 0, IP_MAXPACKET * sizeof(uint8_t));

    if (sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) < 0){
        perror("socket() failed");
        exit (EXIT_FAILURE);
    }
    // setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "eno1", strlen("eno1") + 1);


    eh = (ethernet_header *) packet;
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

    printf("%lu\n", sizeof(ethernet_header));
    tlv_header = (uint16_t * ) &packet[sizeof(ethernet_header) + tlv_offset];

    tlv_type = htons(tlv_header) >> 9;
    tlv_length = htons(tlv_header) & 0x01ff;

    printf("tlv_type: %d , tlv_length: %d\n", tlv_type, tlv_length);
    printf("structure: %04x\n", tlv_header;
    printf("Total packets: %d\n", cnt);
    printf("Goto bed \n");
    
    FILE * fp, * fp2;
    fp = fopen("/tmp/packet", "wb");
    fwrite(packet, 1, packet_len, fp);
    fclose(fp);
 
//     char type_one_mac[MAC_STRING_LEN];
//     mac_address_fmt(tlv_data->data, type_one_mac);
//     printf("TYPE1 MAC: %s\n", type_one_mac);
    tlv_info_string = (uint8_t *) &packet[sizeof(ethernet_frame) + sizeof(*tlv_header) + tlv_offset];
    // init tlv
    // line 205 openlldp
    tlv_offset += sizeof(*tlv_header) + tlv_length;
}

void mac_address_fmt(uint8_t *addr, char *buff) {
    snprintf(buff, MAC_STRING_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}
