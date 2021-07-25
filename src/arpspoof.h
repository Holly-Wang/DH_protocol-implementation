/**
 * @filename: arpspoof.c
 * @author: han bing, hit at weihai
 * @brief: 用于对目标计算机进行arp欺骗
 * @keys: 
 * - 获取主机的MAC地址
 * - 构造伪造的ARP报文
 * - 捕获目标机器的arp请求
 * - 发送arp reply,让victim接受
 * - 发送ping可以检测, 也可以进行毒害
 */
#include "main.h"

/*
    请求报文是 42字节的(没有填充)
    响应报文是 60字节的(包括18字节的填充)
    有用的部分都是42字节
    以太网帧的头解析三个字段, 之后是arp请求和arp响应
*/
#define MAX_SPOOF_FLOOD_HOSTS 2
#define ARP_SPOOF_SIZE 42


typedef struct arp_packet {
    ushort hardware_type;  // 1
    ushort protocol_type;  // 0x0800
    u_char hardware_size;  // 6 mac长度
    u_char protocol_size;  // 4 ip长度
    ushort op_code;        // 1 表示请求, 2表示回应
    u_char sender_mac[6];
    uint32_t sender_ip;
    u_char target_mac[6];
    uint32_t target_ip;
} ARPPacket;


#define MAX_TABLE_SIZE 128
#define MAX_KEY_LENGTH 18
#define MAX_VALUE_LENGTH 18

// =====================================table=====================================================
typedef struct pair {
    char key[MAX_KEY_LENGTH];
    char value[MAX_KEY_LENGTH];
} ARPItem;

typedef struct a_table {
    ARPItem arp_items[MAX_TABLE_SIZE];
    size_t size;
} ARPTable;

void init_table(struct a_table *table OUT_ARG);

size_t insert_into_table(struct a_table *table INOUT_ARG, char *key IN_ARG, char *value IN_ARG);

int find_in_table(struct a_table *table IN_ARG, const char *key IN_ARG);

void show_table(struct a_table *table IN_ARG);

size_t get_arp_table(ARPTable *arp_table OUT_ARG);

// =====================================arp packet================================================
int arp_get_mac(struct a_table *arp_table IN_ARG, const char *ip IN_ARG,
                u_char *temp_mac OUT_ARG);

int arp_spoof_make_packet(u_char *spoof_packet INOUT_ARG, size_t size IN_ARG,
                          const u_char *sender_ip IN_ARG, const u_char *dst_mac IN_ARG,
                          const u_char *target_ip IN_ARG);

/**
 * @brief parse arp packet, for debug
 */
int arp_spoof_parse_packet(const u_char *pkt_buff IN_ARG, size_t size IN_ARG,
                           EtherHdr *ether_hdr OUT_ARG, ARPPacket *arp OUT_ARG);

/**
 * @brief show ethernet frame header
 */
void show_ether(const EtherHdr *etherhdr IN_ARG);

/**
 * @brief show arp packet
 */
void show_arp(const ARPPacket *arp IN_ARG);

/**
 * @brief callback function for pcap_loop() send arp reply, too slow...
 * @return never return
 */
void pkthdr4arp_spoof(u_char *args,
                      const struct pcap_pkthdr *pkthdr IN_ARG,
                      const u_char *pkt_buff IN_ARG);

/**
 * @brief listen the arp packet through the network interface `vmnet8', and send fake arp reply
 * @return never return if succeed, or failed returned error code
 */
int arp_spoof(NO_ARGS);

/**
 * @brief send fake arp packet to the link layer every `timeout` ms, `cnt` times
 * @return never return until received <Ctrl-Break> or size == 0
 */
void arp_spoof_flood(const char ip_list[2][16] IN_ARG, int timeout IN_ARG, int cnt IN_ARG);