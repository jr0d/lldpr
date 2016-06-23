#ifndef LLDPR_H
#define LLDPR_H

#define ETH_P_ALL 0x0003
#define ETH_P_LLDP 0x88CC
#define MAC_STRING_LEN 18     // FF:FF:FF:FF:FF:FF\0

#include <stdint.h>
#include <time.h>

typedef struct ethernet_header{
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
} ethernet_header;


/* macros */

#define calc_offset(O) sizeof(ethernet_header) + O


/* Prototypes */
extern char * mac_address_fmt(uint8_t *addr);
extern uint8_t * fetch_lldp_packet(char * interface, time_t timeout);
#endif // LLDPR_H
