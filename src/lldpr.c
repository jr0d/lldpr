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
#include <poll.h>             // poll(), pollfd

#include <netinet/ip.h>       // IP_MAXPACKET (65535)

#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <linux/if_packet.h>

#include "lldpr.h"
#include "debug.h"

ssize_t recv_t(int sock, uint8_t * packet, uint8_t * hwaddr, time_t timeout) {
    int ret = 0;
    int cnt = 0;
    int i = 0;
    unsigned char match = 0;
    ssize_t packet_len = 0;
    time_t start_time = 0;

    struct pollfd pfd;
    ethernet_header *eh = (ethernet_header *) packet;

    pfd.fd = sock;
    pfd.events = POLLIN;

    start_time = time(NULL);

    while (1) {
        if (time(NULL) - start_time > timeout) {
            fprintf(stderr, "Packet not received prior to timeout. Timeout: %lu\n", timeout);
            exit(1);
        }
        if ((ret = poll(&pfd, 1, 1000)) == -1) {
            perror("Error polling socket");
            exit(EXIT_FAILURE);
        }

        if (ret == 0)
            continue;

        packet_len = recv(sock, packet, IP_MAXPACKET, 0);

        if (packet_len < 0) {
            perror("Problem getting packet");
            exit(EXIT_FAILURE);
        }
        cnt++;

        if (eh->type == htons(ETH_P_LLDP))
            break;

        for (i=0; i<=5; i++) {
            if (eh->src[i] == hwaddr[i]) {
                match = 1;
            } else {
                match = 0;
                break;
            }
        }

        if (match) continue; // Packet emerged from the listening interface

        // if (htons(eh->type) != 0x0800)
        //    printf("Got packet, just not the right one: 0x%04x\n", htons(eh->type));

        memset(packet, 0, IP_MAXPACKET * sizeof(uint8_t));
    }

    debug("LLDP packet received! Ethernet type code: 0x%04x\n", htons(eh->type));
    debug("\nEthernet frame header:\n");

    debug("Destination MAC (this node): %s\n", mac_address_fmt(eh->dest));
    debug("Source MAC: %s\n", mac_address_fmt(eh->src));

    debug("Total packets: %d\n\n", cnt);

    return packet_len;
}

uint8_t * fetch_lldp_packet(char * ifname, time_t timeout) {
    int sock = 0;
    uint8_t *packet = NULL;
    uint8_t mac_address[6];
    struct ifreq ifr;
    struct sockaddr_ll saddr_ll;

    memset(&ifr, 0, sizeof(ifr));
    memset(&saddr_ll, 0, sizeof(saddr_ll));

    packet = (uint8_t *) malloc(IP_MAXPACKET * sizeof(uint8_t));

    if(packet == NULL) {
        perror("Could not allocate memory for packet buffer");
        exit(EXIT_FAILURE);
    }

    memset(packet, 0, IP_MAXPACKET * sizeof(uint8_t));

    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
        perror("socket() failed");
        exit (EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, ifname, strnlen(ifname, 20) + 1);

    ioctl(sock, SIOCGIFINDEX, &ifr);

    if(ifr.ifr_ifindex == 0) {
        fprintf(stderr, "Interface %s does not seem to exist\n", ifname);
        exit(EXIT_FAILURE);
    }

    saddr_ll.sll_ifindex = ifr.ifr_ifindex;
    saddr_ll.sll_family = AF_PACKET;

    debug("Binding to interface %s, if_index %d", ifname, saddr_ll.sll_ifindex);

    if ((bind(sock, (struct sockaddr *) &saddr_ll, sizeof(saddr_ll))) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    ioctl(sock, SIOCGIFHWADDR, &ifr);

    memcpy(&mac_address, (void *) ifr.ifr_hwaddr.sa_data, 6);

    debug("HWADDR: %s", mac_address_fmt(mac_address));


    debug("Entering promiscuous mode on %s", ifname);

    ioctl(sock, SIOCGIFFLAGS, &ifr);

    ifr.ifr_flags |= IFF_PROMISC;

    ioctl(sock, SIOCSIFFLAGS, &ifr);

    recv_t(sock, packet, mac_address, timeout);

    debug("Disabling promiscuous mode");

    ifr.ifr_flags ^= IFF_PROMISC;

    ioctl(sock, SIOCSIFFLAGS, &ifr);

    debug("Closing socket");
    close(sock);

    return packet;
}

char * mac_address_fmt(uint8_t *addr) {
    static char mac_address[MAC_STRING_LEN];
    snprintf(mac_address, MAC_STRING_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return mac_address;
}
