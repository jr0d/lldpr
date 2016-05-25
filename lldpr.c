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


int main()
{
    int sock, status, i;
    uint8_t *ether_frame;

    ether_frame = (uint8_t *) malloc(IP_MAXPACKET * sizeof(uint8_t));
    
    if(ether_frame == NULL) {
        perror("Could not allocate memory for packet buffer");
        exit(EXIT_FAILURE);
    }
    
    memset(ether_frame, 0, IP_MAXPACKET * sizeof(uint8_t));

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock < 0) {
        perror("socket() failed");
        exit (EXIT_FAILURE);
    }
    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "eno1", strlen("eno1") + 1);

    status = recv(sock, ether_frame, IP_MAXPACKET, 0);

    close(sock);

    if (status < 0) {
        perror("Problem getting packet");
        exit(EXIT_FAILURE);
    }

    printf ("Ethernet type code: %u\n", ((ether_frame[12]) << 8) + ether_frame[13]);
	printf ("\nEthernet frame header:\n");
	printf ("Destination MAC (this node): ");
	for (i=0; i<5; i++) {
	    printf ("%02x:", ether_frame[i]);
	}
	printf ("%02x\n", ether_frame[5]);
	printf ("Source MAC: ");
	for (i=0; i<5; i++) {
	    printf ("%02x:", ether_frame[i+6]);
	}
    printf ("%02x\n", ether_frame[11]);
}
