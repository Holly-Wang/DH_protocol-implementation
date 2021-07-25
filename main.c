#include "src/main.h"

char TIME_BUFF[32];

char *get_current_date_time() {
    memset(TIME_BUFF, 0, sizeof(TIME_BUFF));
    time_t tt = time(0);
    strftime(TIME_BUFF, sizeof(TIME_BUFF), "%Y-%m-%d %H:%M:%S", localtime(&tt));
    return TIME_BUFF;
}

void show_packet(const u_char *pkt_buff, size_t size) {
    printf("got packet: %ld bytes\n", size);
    puts("=================================================");
    if (size <= 0) {
        printf("[error], packet size error");
        return;
    }
    for (int i = 0; i < size; ++i) {
        if (i != 0) {
            if (i % 16 == 0) {
                puts("");
            } else if (i % 8 == 0) {
                printf("| ");
            }
        }

        printf("%02x ", pkt_buff[i]);
    }
    puts("\n=================================================");
}

#ifdef NORMAL_COMM_MODE
#define TEST_IP "192.168.234.131"
#define TEST_PORT 9610

#include "src/dh_comm.h"

#ifndef USE_PSK

int main(int argc, char *argv[]) {
    char ip[16] = {0};
    size_t len_ip = strlen(TEST_IP);
    strcpy(ip, TEST_IP);
    ushort port = TEST_PORT;
    if (argc >= 2) {
        if (len_ip > 16) {
            fprintf(stderr, "error: given ip is too long");
            return -1;
        }
        // ip
        memset(ip, 0, 16);
        memcpy(ip, argv[1], strlen(argv[1]));
    }
    if (argc >= 3) {
        // port
        port = strtoul(argv[2], NULL, 10);
    }
#ifdef SERVER
    if (argc >= 4) {
        puts("usage: ./server [ip] [port]");
        return 0;
    }
    server(ip, port);
#elif defined(CLIENT)
    if (argc >= 4) {
        puts("usage: ./client [ip] [port]");
        return 0;
    }
    client(ip, port);
#endif
}

#else

int main(int argc, char *argv[]) {
    char ip[16] = {0};
    size_t len_ip = strlen(TEST_IP);
    strcpy(ip, TEST_IP);
    ushort port = TEST_PORT;
    char psk[32] = "634umfnyfry7ct476t674f35y3sw9xtw";
    if (argc >= 2) {
        memcpy(psk, argv[1], 32);
    }
    if (argc >= 3) {
        if (len_ip > 16) {
            fprintf(stderr, "error: given ip is too long");
            return -1;
        }
        // ip
        memset(ip, 0, 16);
        memcpy(ip, argv[2], strlen(argv[2]));
    }
    if (argc >= 4) {
        // port
        port = strtoul(argv[3], NULL, 10);
    }

#ifdef SERVER
    if (argc >= 5) {
        puts("usage: ./server_safe [psk] [ip] [port]");
        return 0;
    }
    server(ip, port, psk);
#elif defined(CLIENT)
    if (argc >= 5) {
        puts("usage: ./client_safe [psk] [ip] [port]");
        return 0;
    }
    client(ip, port, psk);
#endif
}

#endif

#elif defined(ARP_SPOOF_MODE)

#include "src/arpspoof.h"


int main(int argc, char *argv[]) {
    char ip_list[2][16] = {
            VICTIM_A,
            VICTIM_B
    };
    if (argc >= 2) {
        size_t ip_victim_a = strlen(argv[1]);
        if (ip_victim_a > 15) {
            ip_victim_a = 15;
        }
        memset(ip_list[0], 0, 16);
        memcpy(ip_list[0], argv[1], ip_victim_a);
    }
    if (argc >= 3) {
        size_t ip_victim_b = strlen(argv[2]);
        if (ip_victim_b > 15) {
            ip_victim_b = 15;
        }
        memset(ip_list[1], 0, 16);
        memcpy(ip_list[1], argv[2], ip_victim_b);
    }

    if(argc >= 4){
        puts("usage: ./arp_spoof [ip1] [ip2]");
        return 0;
    }
    arp_spoof_flood(ip_list, 10000, -1);
    return 0;
}

#elif defined(MAN_IN_MIDDLE_MODE)

#include "src/man_in_middle.h"

const u_char VICTIM_A_MAC[6] = {0x00, 0x0c, 0x29, 0x52, 0x8c, 0x17};
const u_char VICTIM_B_MAC[6] = {0x00, 0x0c, 0x29, 0xea, 0x23, 0x21};
const u_char ATTACKER_MAC[6] = {0x00, 0x50, 0x56, 0xc0, 0x00, 0x08}; // attacker


int main() {
    man_in_middle();
}

#else

int main() {
    printf("invalid configuration...\n");
}

#endif

