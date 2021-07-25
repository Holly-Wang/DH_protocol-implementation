//
// Created by bing on 2021/7/18.
//

#ifndef DIFFIE_HELLMAN_MAN_IN_MIDDLE_H
#define DIFFIE_HELLMAN_MAN_IN_MIDDLE_H

#include "dh_protocol.h"
#include <dlfcn.h>

#define MAX_PACKET_COPY_SIZE 1024

typedef struct tcp_pseudo_header {
    u_int src_ip;
    u_int dst_ip;
    u_char zero;    // 0x00
    u_char protocol; // 0x06 tcp
    u_short tcp_length; // 0x1c + sizeof(payload) = len - sizeof(ether) - sizeof(ip)
} PSD_TCP_HEADER;

typedef void PLUGIN_FUNC(unsigned char *tcp_data, unsigned char size);

typedef const char *PLUGIN_DESC_FUNC();

typedef struct pcap_hdl_args {
    pcap_t *handle;
    PLUGIN_FUNC *plugin_func;
} PCAP_HDL_ARGS;

u_short checksum(u_short *buffer, u_short size);

u_short tcp_checksum(u_char *tcp_packet, u_short size, uint ip_src, uint ip_dst);


void print_key_and_generate_parameters(u_char *key, DH_MSG *dh_msg, DH *dh);

void pkt_hdl4man_in_middle(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *pkt_buff);

int man_in_middle();

void *load_plugin_func(const char *file_name, char *desc, size_t size, PLUGIN_FUNC **func);

void do_nothing(unsigned char *tcp_data, unsigned char size);

#endif //DIFFIE_HELLMAN_MAN_IN_MIDDLE_H
