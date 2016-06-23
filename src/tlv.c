//
// Created by jared on 6/2/16.
//

#include <stdio.h>
#include <stdint.h>
#include "lldpr.h"
#include "debug.h"
#include "tlv.h"


lldp_tlv_list * tlv_list_create() {
    lldp_tlv_list * _tlv_list;
    _tlv_list = (lldp_tlv_list *) calloc(1, sizeof(lldp_tlv_list));
    _tlv_list->tlv = NULL;
    _tlv_list->next = NULL;
    return _tlv_list;
}

void tlv_list_push(lldp_tlv_list *head, TLV *tlv) {
    if (head->tlv == NULL) {
        debug("Pushed onto new list : TLV - %d\n", tlv->type);
        head->tlv = tlv;
        return;
    }
    lldp_tlv_list *current = head;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = tlv_list_create();
    current->next->tlv = tlv;
}

lldp_tlv_list * tlv_list_remove_tail(lldp_tlv_list *head) {
    lldp_tlv_list *current = head;
    lldp_tlv_list *previous = current;

    debug("IN tlv_list_remove: TOP");
    debug("CURRENT->NEXT: 0x%p", current->next);
    if (current->next == NULL) {
        // Encountered an empty or single entry list
        debug("FREEING HEAD");
        free(current->tlv);
        return NULL;
    }
    while (current->next != NULL) {
        debug("IN WHILE CURRENT->NEXT: 0x%p", current->next);
        previous = current;
        current = current->next;
    }
    debug("IN tlv_list_remove: BOTTOM : CURRENT->TLV-TYPE : %d\n", current->tlv->type);
    free(current->tlv);
    free(current);
    previous->next = NULL;
    return previous;
}

void tlv_list_destroy(lldp_tlv_list *head) {
    lldp_tlv_list *previous = NULL;
    debug("TLV_DESTROY");
    do {
        previous = tlv_list_remove_tail(head);
    } while(previous != NULL);

    free(head);
}

TLV *get_tlv(lldp_tlv_list *head, uint16_t tlv_type) {
    lldp_tlv_list * current = head;
    while(current->tlv != NULL) {
        if (current->tlv->type == tlv_type)
            return current->tlv;
        current = current->next;
    }
    return NULL;
}

void parse_lldp_packet(uint8_t *packet, lldp_tlv_list *head) {
    /*
     * Iterate over TLVs. Explode TLVs and store them in a linked list. Validations should occur before calling this function
     */

    TLV *current_tlv = NULL;
    uint16_t *tlv_header = 0;
    uint16_t tlv_offset = 0;

    do {
        tlv_header = (uint16_t *) &packet[calc_offset(tlv_offset)];
        current_tlv = (TLV *) calloc(1, sizeof(TLV));
        current_tlv->type = TLV_TYPE(htons(*tlv_header));
        current_tlv->length = TLV_LENGTH(htons(*tlv_header));

        if (current_tlv->length > 0) {
            current_tlv->data = (uint8_t *) calloc(1, current_tlv->length);
            memcpy(current_tlv->data, &packet[calc_offset(tlv_offset) + sizeof(*tlv_header)], current_tlv->length);
        } else
            current_tlv->data = NULL;

        tlv_offset += sizeof(*tlv_header) + current_tlv->length;
        debug("Pushing TLV type : %d\n", current_tlv->type);
        tlv_list_push(head, current_tlv);

    } while(current_tlv->type != 0);
}

void print_tlv(TLV *tlv) {
    size_t one = 1;  // IDEs are supposed to help you write better code?
    uint8_t mgmt_addr_len = 0;
    uint8_t mgmt_addr_type = 0;
    uint8_t tlv_subtype = 0;

    uint16_t msap_ttl = 0;

    char *info_string = NULL;

    printf("TLV: %u\n", tlv->type);
    printf("TLV Length: %d\n", tlv->length);
    printf("TLV info string: ");

    switch (tlv->type) {
        case TLV_LLDPDU_END:
            printf("End of TLV\n");
            break;
        case TLV_CHASSIS_ID:
            tlv_subtype = tlv->data[0];
            printf("SUBTYPE: %d - MSAP ADDRESS: %s\n", tlv_subtype, mac_address_fmt(tlv->data+1));
            break;
        case TLV_PORT_ID:
            tlv_subtype = tlv->data[0];
            if(tlv_subtype == 3) {
                printf("SUBTYPE: %d - PORT ID MAC: %s\n", tlv_subtype, mac_address_fmt(tlv->data+1));
                break;
            } else if(tlv_subtype == 5) {
                info_string = (char *) calloc(1, tlv->length+ 1);
                strncpy(info_string, (const char *) tlv->data+1, tlv->length-one);
                info_string[tlv->length] = '\0';
                printf("SUBTYPE: %d - PORT ID INTERFACE %s\n", tlv_subtype, info_string);
                free(info_string);
                break;
            } else
                printf("SUBTYPE: %d - SUBTYPE unhandled\n", tlv_subtype);
        case TLV_TTL:
            msap_ttl = *(uint16_t *) &tlv->data[0];
            printf("TTL: %d : %04x\n", ntohs(msap_ttl), msap_ttl);
            break;
        case TLV_MGMT_ADDR:
            mgmt_addr_len = tlv->data[0];
            mgmt_addr_type = tlv->data[1];
            printf("MGMT ADDR LEN: %d, TYPE: %d\n", mgmt_addr_len, mgmt_addr_type);
            break;
        default:
            printf("Type unhandled\n");
    }
    printf("\n");
}