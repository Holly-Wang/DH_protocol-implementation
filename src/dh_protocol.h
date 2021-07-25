//
// Created by bing on 2021/7/19.
// remake diffie-hellman key change protocol for arp man-in-middle-attacker
//
    // dh_protocol.h
    #ifndef DIFFIE_HELLMAN_DH_PROTOCOL_H
    #define DIFFIE_HELLMAN_DH_PROTOCOL_H

    #include "main.h"

    #define DH_BUF_SIZE 1024

    /**
     * This first argument is used to pick up errors when a DH is passed
     * instead of a EVP_PKEY
     */
    struct dh_st {
        int pad;
        int version;
        BIGNUM *p;
        BIGNUM *g;
        int32_t length;             /* optional */
        BIGNUM *pub_key;            /* g^x % p */
        BIGNUM *priv_key;           /* x */
        int flags;
        BN_MONT_CTX *method_mont_p;
        /* Place holders if we want to do X9.42 DH */
        BIGNUM *q;
        BIGNUM *j;
        unsigned char *seed;
        int seedlen;
        BIGNUM *counter;
        int references;
        CRYPTO_EX_DATA ex_data;
        const DH_METHOD *meth;
        ENGINE *engine;
        CRYPTO_RWLOCK *lock;
    };

    /*==============================MSG STRUCT===============================*/
    typedef enum dh_msg_type {
        DH_KEY_EXCHANGE_REQ,
        DH_KEY_EXCHANGE_RES,
        DH_DIALOGUE,
        DH_FAIL
    } DH_MSG_TYPE;

    typedef struct dh_head {
        DH_MSG_TYPE type;
        u_char para_size;
    } DH_HEAD;

    typedef struct dh_body_item {
        u_char item_length;
        u_char item[256];
    } DH_BODY_ITEM;

    typedef struct dh_body {
        DH_BODY_ITEM body_item[255];
        u_char valid_length;
    } DH_BODY;

    typedef struct dh_msg {
        DH_HEAD head;
        DH_BODY body;
    } DH_MSG;


    typedef enum dh_key_exchange_pkt_type {
        DH_KEY_EXCHANGE_PKT_TYPE_REQ,
        DH_KEY_EXCHANGE_PKT_TYPE_RES
    } DH_KEY_EXCHANGE_PKT_TYPE;


    /*=============================EXTERN VARIABLES===========================*/
    extern const char MSG_INFO[16][256];
    #ifdef USE_PSK
    extern char PSK[32];
    #endif
    /*=============================EXTERN FUNCTIONS===========================*/
    // PART ONE: ABOUT MESSAGE
    /** used by functions for making packet
     * get dh message's body params from the packet.
     */
    bool dh_put_msg_params(DH_MSG *dh_msg IN_ARG, u_char *out OUT_ARG, size_t *max_size INOUT_ARG);

    /**
     * parse dh protocol packet(u_char array) to dh_msg
     */
    bool dh_parse_packet(u_char *pkt IN_ARG, DH_MSG *dh_msg OUT_ARG);

    /**
     * check dh protocol params in struct dh_st
     */
    bool dh_check_protocol_params(DH *d IN_ARG);

    /**
     * calculate the shared key with struct dh_st and pub_key
     */
    bool dh_generate_shared_key(DH *d IN_ARG, BIGNUM *pub_key IN_ARG, u_char *shared_key OUT_ARG);

    /**
     * used by function `dh_key_exchange_request/response'
     * convert struct dh_msg to msg...
     */
    bool dh_cvt_dh2msg(DH *dh IN_ARG, DH_KEY_EXCHANGE_PKT_TYPE flag IN_ARG,
                    DH_MSG *dh_msg OUT_ARG);

    /**
     * not safe
     * cvt struct dh_msg to bytes
     */
    int dh_cvt_dh_msg2bytes(DH_MSG *dh_msg IN_ARG, u_char *out OUT_ARG, size_t max_size IN_ARG);


    /**
     * make key exchange request packet...
     */
    bool dh_key_exchange_request(DH *d OUT_ARG, DH_MSG *dh_msg OUT_ARG);

    /**
     * make key exchange response packet...
     */
    bool dh_key_exchange_response(DH_MSG *dh_msg_req,
                                DH *d OUT_ARG, DH_MSG *dh_msg OUT_ARG);

    /**
     * make communication packet...
     */
    bool dh_dialogue(DH_MSG *dh_msg_req, u_char *data, uint8_t size);


    /**
     * use aes-256-gcm to encrypt plaintext 'in' with 'key',
     * save in 'out'
     * 'outlen' gives the the maxsize of out
     * function set 'outlen' before return
     * if key is all-zero, return false;
     */
    bool dh_aes_256_gcm_encrypt(u_char *key IN_ARG,
                                u_char *in IN_ARG, size_t in_len IN_ARG,
                                u_char *out OUT_ARG);

    /**
     * use aes-256-gcm to encrypt ciphertext 'in' with 'key',
     */
    bool dh_aes_256_gcm_decrypt(u_char *key IN_ARG,
                                u_char *in IN_ARG, size_t in_len IN_ARG,
                                u_char *out OUT_ARG);

    // PART TWO OTHER FUNCTION
    /**
     * print error and addi_err_msg
     */
    void dh_error_handle(char *addi_err_msg IN_ARG);

    /**
     * show dh message: head ...body
     */
    void dh_show_message(DH_MSG *dh_msg IN_ARG);

    /**
     * check input string: equals str.strip()..
     */
    void dh_check_input_str(char *input INOUT_ARG, int *size INOUT_ARG);

    /**
     * show params in dh_st
     */
    void dh_show_protocol_params(DH *dh IN_ARG);

    void dh_show_shared_key(u_char *shared_key IN_ARG);

    /**
     * put item into dh_msg
     */
    bool dh_set_dh_msg_item(DH_MSG *dh_msg INOUT_ARG, u_char *item IN_ARG, size_t item_size IN_ARG);

    /**
     * item <= dh_msg->body.items[i].item
     * item_size <= dh_msg_body.items[i].item_size
     */
    uint8_t dh_get_dh_msg_item(DH_MSG *dh_msg IN_ARG, size_t i IN_ARG, u_char *item OUT_ARG, size_t item_size IN_ARG);
    /*========================================================================*/


    #endif //DIFFIE_HELLMAN_DH_PROTOCOL_H