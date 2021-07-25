// dh_comm.h
#ifndef DIFFIE_HELLMAN_DH_COMM_H
#define DIFFIE_HELLMAN_DH_COMM_H

#include "dh_protocol.h"

typedef struct thread_args {
    int client_socket;
    bool *run_flag;
    u_char key[32];
} THREAD_ARGS;
// ==========================server=======================
/**
 * @return server's listen_fd
 */
int server_init(const char *bind_ip IN_ARG, u_short bind_port IN_ARG);

/**
 * @return client's sock_fd
 */
int client_init(const char *serv_ip IN_ARG, u_short serv_port IN_ARG);

void *recv_thread(void *args IN_ARG);

int start_dialog(int sock_fd IN_ARG, u_char *shared_key IN_ARG);

/**
 * server' msg read wrapper
 */
int recv_msg(int client_fd IN_ARG, char *buf OUT_ARG, size_t size IN_ARG);

/**
 * server' msg write wrapper
 */
int send_msg(int client_fd IN_ARG, char *buf OUT_ARG, size_t size IN_ARG);

/**
 * never return until error or received 'q'
 */
#ifndef USE_PSK
int server(const char *bind_ip IN_ARG, u_short bind_port IN_ARG);
#else

int server(const char *bind_ip IN_ARG, u_short bind_port IN_ARG, const char *psk);

#endif

/**
 * never return until client send 'q' to server
 */
#ifndef USE_PSK
int client(const char *serv_ip IN_ARG, u_short serv_port IN_ARG);
#else

int client(const char *serv_ip IN_ARG, u_short serv_port IN_ARG, const char *psk);

#endif

void check_received_msg(const char *text);


#endif // DIFFIE_HELLMAN_DH_COMM_H