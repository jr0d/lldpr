#ifndef LLDPR_H
#define LLDPR_H

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
} TLV;

struct lldp_tlv_list {
    TLV *next;
    TLV *tlv;
};

/* Prototypes */
extern void mac_address_fmt(uint8_t *addr, char *buff);

#endif // LLDPR_H
