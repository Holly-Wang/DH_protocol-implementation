// dh_comm.c
#include "dh_comm.h"


/**
 * @return server's listen_fd
 */
int server_init(const char *bind_ip IN_ARG, u_short bind_port IN_ARG) {
    // create a socket
    int listen_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        dh_error_handle("create socket error.\n");
        return -1;
    }
    // set socket option, re-use-addr
    const int on = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    // bind
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(bind_ip);
    server_addr.sin_port = htons(bind_port);
    int ret = bind(listen_fd, (struct sockaddr *) &server_addr, sizeof(server_addr));
    if (ret != 0) {
        dh_error_handle("server_init(): bind error.");
        return -1;
    }
    // listen
    ret = listen(listen_fd, 6);
    if (ret == -1) {
        // errno is set.
        dh_error_handle("server_init(): listen error.");
        return -1;
    }
    // return listen_fd;
    return listen_fd;
}


/**
 * @return client's sock_fd
 */
int client_init(const char *serv_ip IN_ARG, u_short serv_port IN_ARG) {
    // create a socket
    int sock_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        dh_error_handle("client_init(): socket() error.");
    }
    // connect to the peer
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(serv_ip);
    server_addr.sin_port = htons(serv_port);
    int ret = connect(sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr));
    if (ret == -1) {
        dh_error_handle("client_init(): connect() error.");
        return -1;
    }
    printf("server(): connection %s: %d <==> %s: %d established...\n", serv_ip, serv_port,
           inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));
    // return sock_fd
    return sock_fd;
}


void *recv_thread(void *args) {
    THREAD_ARGS *t_args = (THREAD_ARGS *) args;
    int sockfd = t_args->client_socket;
    u_char recv_buf[DH_BUF_SIZE];
    u_char plain_text[DH_BUF_SIZE];
    u_char cipher_text[DH_BUF_SIZE];
    DH_MSG dh_msg;
    u_char sk[32] = {0};
    memcpy(sk, t_args->key, 32);
    while (true) {
        recv_msg(sockfd, (char *) recv_buf, DH_BUF_SIZE);
        dh_parse_packet(recv_buf, &dh_msg);
        int data_len;
        if (dh_msg.head.type == DH_DIALOGUE && dh_msg.head.para_size == 0x01) {
            data_len = dh_get_dh_msg_item(&dh_msg, 0, cipher_text, DH_BUF_SIZE);
            dh_aes_256_gcm_decrypt(sk, cipher_text, data_len, plain_text);
            // print it
            printf("\r<< %s \n>> ", plain_text);
            fflush(stdout);
            // check output
            check_received_msg((char *) plain_text);
            if (strcmp((char *) plain_text, "q") == 0 || strcmp((char *) plain_text, "Q") == 0) {
                puts("client socket close.");
                break;
            }
            memset(recv_buf, 0, DH_BUF_SIZE);
            memset(plain_text, 0, DH_BUF_SIZE);
            memset(cipher_text, 0, DH_BUF_SIZE);
        }
    }
    *(t_args->run_flag) = false;
    puts("\033[33mthe connection has been killed by peer.\033[30m \npress any key to quit");
    return NULL;
}

int start_dialog(int sock_fd, u_char *shared_key) {
    puts("=============================communication====================================");
    // buffer
    char send_buf[DH_BUF_SIZE];
    char cipher_buf[DH_BUF_SIZE];
    char input_buf[DH_BUF_SIZE];
    DH_MSG dh_msg_dialogue = {0};
    // create a new thread for read...
    THREAD_ARGS a;
    bool run_flag = true;
    a.client_socket = sock_fd;
    a.run_flag = &run_flag;
    memcpy(a.key, shared_key, 32);
    pthread_t tid;
    int ret = pthread_create(&tid, NULL, recv_thread, &a);
    if (ret != 0) {
        dh_error_handle("server(): thread create error.");
        return -1;
    }
    // main thread for write
    int real_input_size;
    while (run_flag) {
        memset(send_buf, 0, DH_BUF_SIZE);
        memset(cipher_buf, 0, DH_BUF_SIZE);
        memset(input_buf, 0, DH_BUF_SIZE);
        memset(&dh_msg_dialogue, 0, sizeof(DH_MSG));

        // input 
        printf(">> ");
        fgets(input_buf, DH_BUF_SIZE, stdin);
        if (run_flag == false) {
            return 0;
        }
        // check input
        real_input_size = (int) strlen(input_buf);
        dh_check_input_str(input_buf, &real_input_size);
        if (strcmp(input_buf, "q") == 0 || strcmp(input_buf, "Q") == 0) {
            puts("client socket close.");
            run_flag = false;
        }
        if (real_input_size == 0) {
            printf(">>");
            continue;
        }
        // encrypt
        dh_aes_256_gcm_encrypt(shared_key, (u_char *) input_buf, real_input_size, (u_char *) cipher_buf);
        dh_dialogue(&dh_msg_dialogue, (u_char *) cipher_buf, strlen(cipher_buf));
        ret = dh_cvt_dh_msg2bytes(&dh_msg_dialogue, (u_char *) send_buf, DH_BUF_SIZE);
        ret = send_msg(sock_fd, send_buf, ret);
        // send error, break
        if (ret == -1) {
            return -1;
        }
    }
    return 0;
}

/**
 * never return
 */
#ifndef USE_PSK

int server(const char *bind_ip IN_ARG, u_short bind_port IN_ARG) {
#else

    int server(const char *bind_ip IN_ARG, u_short bind_port IN_ARG, const char *psk) {
        SHA256((u_char *) psk, 32, (u_char *) PSK);
#endif
    // ...
    char server_buf[DH_BUF_SIZE];
    char shared_key[32];
    char pubkey_str[65];

    DH *dh_rsp = DH_new();
    DH_MSG dh_msg_key_ex_req = {0};
    DH_MSG dh_msg_key_ex_rsp = {0};

    // init server
    int listen_fd = server_init(bind_ip, bind_port);
    if (listen_fd < 0) {
        goto clear;
    }
    printf("will bind %s:%d\n", bind_ip, bind_port);
    // accept
    struct sockaddr_in client_addr = {0};
    socklen_t client_addr_len = sizeof(client_addr);
    int sock_fd = accept(listen_fd, (struct sockaddr *) &client_addr, &client_addr_len);

    // ........... connection established ...........//
    printf("server(): connection %s: %d <==> %s: %d established...\n", bind_ip, bind_port,
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    // ........... dh protocol........................//
    // 1. got g, p Y_a
    int ret = recv_msg(sock_fd, server_buf, DH_BUF_SIZE);
    if (ret == -1) {
        goto err;
    }
    dh_parse_packet((u_char *) server_buf, &dh_msg_key_ex_req);
    puts("key change request from client.");
    dh_show_message(&dh_msg_key_ex_req);

    // 2. set g, p to dh_rsp with req and generate dh_msg in rsp
    ret = dh_key_exchange_response(&dh_msg_key_ex_req, dh_rsp, &dh_msg_key_ex_rsp);
    if (ret == false) {
        goto err;
    }
    // 3. send Y_b
    memset(server_buf, 0, DH_BUF_SIZE);
    ret = dh_cvt_dh_msg2bytes(&dh_msg_key_ex_rsp, (u_char *) server_buf, DH_BUF_SIZE);
    if (ret == false) {
        goto err;
    }
    ret = send_msg(sock_fd, server_buf, ret);
    if (ret == -1) {
        goto err;
    }
    puts("key change response to client.");
    dh_show_message(&dh_msg_key_ex_rsp);
    // 4. generate the shared key
    BIGNUM *pub_key = NULL;
    dh_get_dh_msg_item(&dh_msg_key_ex_req, 2, (u_char *) pubkey_str, 65);
    BN_hex2bn(&pub_key, pubkey_str);
    dh_generate_shared_key(dh_rsp, pub_key, (u_char *) shared_key);
    if (ret == false) {
        BN_free(pub_key);
        goto err;
    }
    puts("compute shared key successfully!");
    dh_show_shared_key((u_char *) shared_key);
    start_dialog(sock_fd, (u_char *) shared_key);
    err:
    close(sock_fd);
    close(listen_fd);
    clear:
    DH_free(dh_rsp);
    exit(-1);
}


/**
 * never return until client send 'q' to server
 */
#ifndef USE_PSK

int client(const char *serv_ip IN_ARG, u_short serv_port IN_ARG) {
#else

    int client(const char *serv_ip IN_ARG, u_short serv_port IN_ARG, const char *psk) {
        SHA256((u_char *) psk, 32, (u_char *) PSK);
#endif
    // ...
    printf("will connected to %s:%d\n", serv_ip,serv_port);
    char client_buf[DH_BUF_SIZE];
    char shared_key[32];
    u_char pubkey_str[65];

    DH *dh_req = DH_new();
    DH_MSG dh_msg_key_ex_req = {0};
    DH_MSG dh_msg_key_ex_rsp = {0};

    // init server
    int sock_fd = client_init(serv_ip, serv_port);
    if (sock_fd < 0) {
        goto clear;
    }
    // ........... dh protocol........................//
    // 1. got g, p Y_a
    int ret = dh_key_exchange_request(dh_req, &dh_msg_key_ex_req);
    if (ret == false) {
        goto err;
    }
    // 2. send g p Y_a
    memset(client_buf, 0, DH_BUF_SIZE);
    ret = dh_cvt_dh_msg2bytes(&dh_msg_key_ex_req, (u_char *) client_buf, DH_BUF_SIZE);
    if (ret == false) {
        goto err;
    }
    ret = send_msg(sock_fd, client_buf, ret);
    if (ret == -1) {
        goto err;
    }
    // 3. wait for Y_b
    ret = recv_msg(sock_fd, client_buf, DH_BUF_SIZE);
    if (ret == -1) {
        goto err;
    }
    dh_parse_packet((u_char *) client_buf, &dh_msg_key_ex_rsp);
    puts("key change response from server.");
    dh_show_message(&dh_msg_key_ex_rsp);

    // 4. generate the shared key
    BIGNUM *pub_key = NULL;
    dh_get_dh_msg_item(&dh_msg_key_ex_rsp, 0, pubkey_str, 65);
    BN_hex2bn(&pub_key, (char *) pubkey_str);
    dh_generate_shared_key(dh_req, pub_key, (u_char *) shared_key);
    if (ret == false) {
        BN_free(pub_key);
        goto err;
    }
    puts("compute shared key successfully!");
    dh_show_shared_key((u_char *) shared_key);
    start_dialog(sock_fd, (u_char *) shared_key);
    err:
    close(sock_fd);
    clear:
    DH_free(dh_req);
    exit(-1);
}

/**
 * msg read wrapper
 */
int recv_msg(int client_fd IN_ARG, char *buf OUT_ARG, size_t size IN_ARG) {
    // clear memory
    memset(buf, 0, size);
    // read
    int ret = (int) read(client_fd, buf, size);
    if (ret == -1) {
        dh_error_handle("server_recv_msg(): read error!");
    }
    return ret;
}

/**
 * msg write wrapper
 */
int send_msg(int client_fd IN_ARG, char *buf OUT_ARG, size_t size IN_ARG) {
    int send_len = (int) write(client_fd, buf, size);
    if (send_len == -1) {
        dh_error_handle("server_send_msg(): write error!");
    }
    return send_len;
}

void check_received_msg(const char *text) {
    size_t t_len = strlen(text);
    for (size_t i = 0; i < t_len; ++i) {
        if (isascii(text[i]) == 0) {
            printf("\r\033[1;32mThe message seems to contain invalid characters. Key agreement failed or "
                   "your connection may be intercepted by a middleman.\n"
                   "We recommend that you enter 'q' to end this connection\n\033[0m\n>> ");
            fflush(stdout);
            break;
        }
    }
}