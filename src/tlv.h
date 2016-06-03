/* Many of these definitions were copied from tlv/tlv.h of the openLLDP project.
 * Per their instruction, I will include their copyright and license

 Copyright (c) 2010, OpenLLDP Project
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright notice, this
list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

Neither the name of the OpenLLDP Project nor the names of its contributors may
be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


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

/* CHASSIS ID SUBTYPES */

#define CHASSIS_ID_CHASSIS_COMPONENT 0x01
#define CHASSIS_ID_INTERFACE_ALIAS 0x02
#define CHASSIS_ID_PORT_COMPONANT 0x3
#define CHASSIS_ID_MAC_ADDRESS 0x4
#define CHASSIS_ID_NETWORK_ADDRESS 0x5
#define CHASSIS_ID_INTERFACE_NAME    0x6
#define CHASSIS_ID_LOCALLY_ASSIGNED  0x7

/* PORT ID SUBTYPES */

#define PORT_ID_INTERFACE_ALIAS  1
#define PORT_ID_PORT_COMPONENT   2
#define PORT_ID_MAC_ADDRESS      3
#define PORT_ID_NETWORK_ADDRESS  4
#define PORT_ID_INTERFACE_NAME   5
#define PORT_ID_AGENT_CIRCUIT_ID 6
#define PORT_ID_LOCALLY_ASSIGNED 7

/* SYSTEM CAPABILITIES */
#define SYSTEM_CAPABILITY_OTHER     1
#define SYSTEM_CAPABILITY_REPEATER  2
#define SYSTEM_CAPABILITY_BRIDGE    4
#define SYSTEM_CAPABILITY_WLAN      8
#define SYSTEM_CAPABILITY_ROUTER    16
#define SYSTEM_CAPABILITY_TELEPHONE 32
#define SYSTEM_CAPABILITY_DOCSIS    64
#define SYSTEM_CAPABILITY_STATION   128

/* MANAGEMENT ADDRESS IANA TYPES */
/* IANA Family Number Assignments */
/* http://www.iana.org/assignments/address-family-numbers */
#define IANA_RESERVED_LOW     0
#define IANA_IP               1
#define IANA_IP6              2
#define IANA_NSAP             3
#define IANA_HDLC             4
#define IANA_BBN_1822         5
#define IANA_802              6
#define IANA_E_163            7
#define IANA_E_164_ATM        8
#define IANA_F_69             9
#define IANA_X_121           10
#define IANA_IPX             11
#define IANA_APPLETALK       12
#define IANA_DECNET_IV       13
#define IANA_BANYAN_VINES    14
#define IANA_E_164_NSAP      15
#define IANA_DNS             16
#define IANA_DISTINGUISHED   17
#define IANA_AS_NUMBER       18
#define IANA_XTP_IPV4        19
#define IANA_XTP_IPV6        20
#define IANA_XTP_XTP         21
#define IANA_FIBRE_PORT_NAME 22
#define IANA_FIBRE_NODE_NAME 23
#define IANA_GWID            24
#define IANA_AFI_L2VPN       25
// Everything from 26 to 65534 is Unassigned
#define IANA_RESERVED_HIGH   65535
/* End IANA Family Number Assignments */

/* ORG IEEE 802.1 */
/* ORG IEEE 802.3 */

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
void tlv_list_push(lldp_tlv_list *head, TLV *tlv);
void tlv_list_destroy(lldp_tlv_list *head);
lldp_tlv_list * tlv_list_create();
lldp_tlv_list * tlv_list_remove_tail(lldp_tlv_list *head);

extern void parse_lldp_packet(uint8_t *packet, lldp_tlv_list *head);
extern void print_tlv(TLV *tlv);

#endif //LLDPR_TLV_H
