#ifndef DIFFIE_HELLMAN_MAIN_H
#define DIFFIE_HELLMAN_MAIN_H

#include <time.h>
#include <stdio.h>
#include <error.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

//#define DEBUG_FLAG
#define IN_ARG
#define OUT_ARG
#define INOUT_ARG
#define NO_ARGS
//#define DEBUG_FLAG

#define DEVICE_NAME "vmnet8"
#define VICTIM_A "192.168.234.131"
#define VICTIM_B "192.168.234.130"

/*Ethernet Frame Header*/
typedef struct ether_hdr {
    u_char dst_mac[6];
    u_char src_mac[6];
    ushort type;
} EtherHdr;

/* IP header */
typedef struct ip_header {
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src, ip_dst;
} IPHeader;

/*TCP Header*/
typedef struct tcp_header {
    u_short th_sport;
    u_short th_dport;
    u_int th_seq;
    u_int th_ack;
    u_char th_offset;
    u_char th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
} TCPHeader;

/*extern buffer*/
extern char TIME_BUFF[32];

extern const u_char VICTIM_A_MAC[6];
extern const u_char VICTIM_B_MAC[6];
extern const u_char ATTACKER_MAC[6];

/**
 * @brief date time function
 */
char *get_current_date_time(NO_ARGS);

/**
 * @brief show packet with hex
 */
void show_packet(const u_char *pkt_buff IN_ARG, size_t size IN_ARG);

#endif