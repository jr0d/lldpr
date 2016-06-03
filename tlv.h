//
// Created by jared on 6/2/16.
//

#ifndef LLDPR_TLV_H
#define LLDPR_TLV_H

#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

/* TLV globals */

#define TLV_LLDPDU_END 0x00
#define TLV_CHASSIS_ID 0x01
#define TLV_PORT_ID 0x02
#define TLV_TTL 0x03
#define TLV_PORT_DESC 0x04
#define TLV_SYSNAME 0x05
#define TLV_SYS_DESC 0x06
#define TLV_SYS_CAP 0x07
#define TLV_MGMT_ADDR 0x08
#define TLV_RESV_START 0x09 // Reserved Start
#define TLV_RESV_END 0x7e   // Reserved End
#define TLV_ORG_SPEC 0x7f   // Organization specific, we probably wont support any of these

/* typedefs */
typedef struct TLV{
    uint8_t type;
    uint16_t length;
    uint8_t *data;
} TLV;

typedef struct lldp_tlv_list {
    struct lldp_tlv_list *next;
    TLV *tlv;
} lldp_tlv_list;

/* Essentail data structures */

struct tlv_chassis_id {
    uint8_t subtype;
    uint8_t * chassis_id;
};

struct tlv_port_id {
    uint8_t subtype;
    uint8_t * port_id;
};

/* macros */

#define TLV_TYPE(U16BE) (uint8_t) (U16BE >> 9)
#define TLV_LENGTH(U16BE) (uint16_t) (U16BE & 0x01ff)


/* prototypes */

lldp_tlv_list * tlv_list_create();
void tlv_list_push(lldp_tlv_list *head, TLV *tlv);

extern void parse_lldp_packet(uint8_t *packet, lldp_tlv_list *head);
extern void print_tlv(TLV *tlv);

#endif //LLDPR_TLV_H
