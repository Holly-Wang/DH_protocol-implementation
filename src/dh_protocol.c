// dh_protocol.c
#include "dh_protocol.h"

const char MSG_INFO[16][256] = {
        "key exchange request",
        "key exchange response",
        "dialogue",
        "fail"
};

const unsigned char DH_GCM_IV[12] = {
        0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0,
        0xee, 0xd0, 0x66, 0x84
};

const unsigned char DH_GCM_AAD[16] = {
        0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b,
        0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78, 0xde
};

#ifdef USE_PSK
char PSK[32] = {0};
#endif

/** used by functions for making packet
 * get dh message's body params from the packet.
 */
bool dh_put_msg_params(DH_MSG *dh_msg, u_char *out, size_t *max_size) {
    uint8_t param_count = dh_msg->head.para_size;
    uint8_t temp_param_size;
    int idx = 0;
    int new_idx;
    for (uint8_t i = 0; i < param_count; ++i) {
        temp_param_size = dh_msg->body.body_item[i].item_length;
        new_idx = idx + temp_param_size + 1;
        if (new_idx > *max_size) {
            dh_error_handle("dh_put_msg_params(): buffer too small!");
            memset(out, 0, *max_size);
            return false;
        }
        out[idx] = temp_param_size;
        memcpy(out + idx + 1, dh_msg->body.body_item[i].item, temp_param_size);
        idx = new_idx;
    }
    *max_size = idx;
    return true;
}

/**
 * parse dh protocol packet(u_char array) to dh_msg
 */
bool dh_parse_packet(u_char *pkt, DH_MSG *dh_msg) {
    dh_msg->head.type = pkt[0];
    dh_msg->head.para_size = pkt[1];
    dh_msg->body.valid_length = pkt[1];
    uint8_t temp_param_size;
    int idx = 2;
    char temp_buf[DH_BUF_SIZE];
    for (uint8_t i = 0; i < dh_msg->head.para_size; ++i) {
        memset(temp_buf, 0, DH_BUF_SIZE);
        temp_param_size = pkt[idx];
        dh_msg->body.body_item[i].item_length = temp_param_size;
        memcpy(dh_msg->body.body_item[i].item, pkt + idx + 1, temp_param_size);
        idx += temp_param_size + 1;
    }
    return true;
}

/**
 * check dh protocol params in struct dh_st
 */
bool dh_check_protocol_params(DH *d) {
    int res = 0;
    int ret = DH_check(d, &res);
    if (ret != 1) {
        dh_error_handle("DH_check err!");
        if (res & DH_CHECK_P_NOT_PRIME)
            dh_error_handle("p value is not prime");
        if (res & DH_CHECK_P_NOT_SAFE_PRIME)
            dh_error_handle("p value is not a safe prime");
        if (res & DH_UNABLE_TO_CHECK_GENERATOR)
            dh_error_handle("unable to check the generator value");
        if (res & DH_NOT_SUITABLE_GENERATOR)
            dh_error_handle("the g value is not a generator");
        return false;
    }
    return true;
}

/**
 * calculate the shared key with struct dh_st and pub_key
 */
bool dh_generate_shared_key(DH *d, BIGNUM *pub_key, u_char *shared_key) {
    if (pub_key == NULL) {
        dh_error_handle("dh_generate_shared_key(): pub key is null");
        return false;
    } else {
        int res = DH_compute_key(shared_key, pub_key, d);
#ifdef USE_PSK
        char old_shared_key[32];
        memcpy(old_shared_key, shared_key, 32);
        show_packet((u_char *) PSK, 32);
        dh_aes_256_gcm_encrypt((u_char *) PSK, (u_char *) old_shared_key, 32, shared_key);
#endif
        if (res < 1) {
            dh_error_handle("compute shared key error.");
            return false;
        }
        return true;
    }
}

/**
 * used by function `dh_key_exchange_request/response'
 * convert struct dh_msg to msg...
 */
bool dh_cvt_dh2msg(DH *dh,
                   DH_KEY_EXCHANGE_PKT_TYPE flag,
                   DH_MSG *dh_msg) {
    if (flag == DH_KEY_EXCHANGE_PKT_TYPE_REQ) {
        dh_msg->head.type = DH_KEY_EXCHANGE_REQ;
        dh_msg->head.para_size = 3;
        dh_msg->body.valid_length = 0;
        char *prime = BN_bn2hex(dh->p);
        char *generator = BN_bn2hex(dh->g);
        char *pubkeyA = BN_bn2hex(dh->pub_key);
        dh_set_dh_msg_item(dh_msg, (u_char *) prime, strlen(prime));
        dh_set_dh_msg_item(dh_msg, (u_char *) generator, strlen(generator));
        dh_set_dh_msg_item(dh_msg, (u_char *) pubkeyA, strlen(pubkeyA));
        OPENSSL_free(prime);
        OPENSSL_free(generator);
        OPENSSL_free(pubkeyA);
    } else {
        dh_msg->head.type = DH_KEY_EXCHANGE_RES;
        dh_msg->head.para_size = 1;
        dh_msg->body.valid_length = 0;
        char *pubkey_B = BN_bn2hex(dh->pub_key);
        dh_set_dh_msg_item(dh_msg, (u_char *) pubkey_B, strlen(pubkey_B));
        OPENSSL_free(pubkey_B);
    }
#ifdef DEBUG_FLAG
    dh_show_message(dh_msg);
#endif
    return true;
}

/**
 * not safe
 * cvt struct dh_msg to bytes
 */
int dh_cvt_dh_msg2bytes(DH_MSG *dh_msg, u_char *out, size_t max_size) {
    out[0] = dh_msg->head.type;
    out[1] = dh_msg->head.para_size;
    max_size -= 2;
    dh_put_msg_params(dh_msg, out + 2, &max_size);
    return (int) max_size + 2;
}


/**
 * make key exchange request packet...
 */
bool dh_key_exchange_request(DH *dh, DH_MSG *dh_msg) {
    int ret;
    // g = 2, got p A
    ret = DH_generate_parameters_ex(dh, 256, DH_GENERATOR_2, NULL);
    if (ret != 1) {
        dh_error_handle("DH_generate_parameters_ex() error.");
        return false;
    }
    // check g p
    ret = dh_check_protocol_params(dh);
    if (ret == false) {
        return false;
    }
    // set private key X_a randomly and compute the public key
    // here assert g, p is valid
    ret = DH_generate_key(dh);
    if (ret != 1) {
        dh_error_handle("DH_generate_key() error!");
    }
#ifdef DEBUG_FLAG
    dh_show_protocol_params(dh);
#endif
    dh_cvt_dh2msg(dh, DH_KEY_EXCHANGE_PKT_TYPE_REQ, dh_msg);
    return true;
}

/**
 * make key exchange response packet...
 */
bool dh_key_exchange_response(DH_MSG *dh_msg_req, DH *d, DH_MSG *dh_msg) {
    // got g, p
    char prime[65] = {0};
    char generator[65] = {0};
    uint8_t size_p = 65;
    uint8_t size_g = 65;
    if (dh_msg_req->head.type != DH_KEY_EXCHANGE_REQ) {
        dh_error_handle("dh_key_exchange_response(): request packet type error");
        return false;
    }
    if (dh_msg_req->head.para_size != 0x03) {
        dh_error_handle("dh_key_exchange_response(): request packet args error");
        return false;
    }
    // here assert the packet is valid
    dh_get_dh_msg_item(dh_msg_req, 0, (u_char *) prime, size_p);
    dh_get_dh_msg_item(dh_msg_req, 1, (u_char *) generator, size_g);
    // set d
    BN_hex2bn(&(d->p), prime);
    BN_hex2bn(&(d->g), generator);
    // print dh_st
#ifdef DEBUG_FLAG
    dh_show_protocol_params(d);
#endif
    // set private key X_b randomly and generate public key Y_b
    int ret = DH_generate_key(d);
    if (ret != 1) {
        // make a fail packet...
        dh_msg->head.type = DH_FAIL;
        dh_error_handle("DH_generate_key() error!");
        return false;
    }
    // params -> dh_msg
    dh_cvt_dh2msg(d, DH_KEY_EXCHANGE_PKT_TYPE_RES, dh_msg);
    return true;

}

/**
 * make communication packet...
 */
bool dh_dialogue(DH_MSG *dh_msg_req, u_char *data, uint8_t size) {
    if (size > (uint8_t) 255) {
        dh_error_handle("dh_communication(): packet too large");
        return false;
    }
    dh_msg_req->head.type = DH_DIALOGUE;
    dh_msg_req->head.para_size = 1;
    dh_set_dh_msg_item(dh_msg_req, data, size);
    return true;
}


/**
 * use aes-256-gcm to encrypt plaintext 'in' with 'key',
 * save in 'out'
 * 'outlen' gives the the maxsize of out
 * function set 'outlen' before return
 * if key is all-zero, return false;
 */
bool dh_aes_256_gcm_encrypt(u_char *key,
                            u_char *in, size_t in_len,
                            u_char *out) {
    int out_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(DH_GCM_IV), NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, DH_GCM_IV);
    EVP_EncryptUpdate(ctx, NULL, &out_len, DH_GCM_AAD, sizeof(DH_GCM_AAD));
    EVP_EncryptUpdate(ctx, out, &out_len, in, (int) in_len);
    EVP_EncryptFinal_ex(ctx, out, &out_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

/**
 * use aes-256-gcm to encrypt ciphertext 'in' with 'key',
 */
bool dh_aes_256_gcm_decrypt(u_char *key,
                            u_char *in, size_t in_len,
                            u_char *out) {
    int out_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(DH_GCM_IV), NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, DH_GCM_IV);
    EVP_DecryptUpdate(ctx, NULL, &out_len, DH_GCM_AAD, sizeof(DH_GCM_AAD));
    EVP_DecryptUpdate(ctx, out, &out_len, in, (int) in_len);
    EVP_DecryptFinal_ex(ctx, out, &out_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;

}

// PART TWO OTHER FUNCTION
/**
 * print error and addi_err_msg
 */
void dh_error_handle(char *addi_err_msg) {
    fprintf(stderr, "%s errno: %d\n", addi_err_msg, errno);
}


void dh_show_message(DH_MSG *dh_msg) {
    puts("================================head=================================");
    printf("type: %s(%d)  para_count: %d\n", MSG_INFO[dh_msg->head.type], dh_msg->head.type, dh_msg->head.para_size);
    puts("================================body=================================");
    for (int i = 0; i < dh_msg->body.valid_length; i++) {
        printf("param %d: %s \nsize: %d\n", i, dh_msg->body.body_item[i].item, dh_msg->body.body_item[i].item_length);
    }
    puts("=====================================================================");
}

void dh_check_input_str(char *input, int *size) {
    // must be test
    char dst[DH_BUF_SIZE];
    size_t front = 0;
    size_t back = *size - 1;
    while (front < back && (input[front] == ' ' ||
                            input[front] == '\0' ||
                            input[front] == '\t' ||
                            input[front] == '\n' ||
                            input[front] == '\r')) {
        front++;
    }
    if (front == back) {
        memset(input, 0, *size);
        return;
    }
    while (back > 0 && (input[back] == ' ' ||
                        input[back] == '\0' ||
                        input[back] == '\t' ||
                        input[back] == '\n' ||
                        input[back] == '\r')) {
        back--;
    }
    back++;
#ifdef DEBUG_FLAG
    printf("dh_check_input_str(): %ld, %ld\n", front, back);
#endif
    if (front < back) {
        memcpy(dst, input, *size);
        memset(input, 0, *size);
        *size = (int) (back - front);
        if (*size > 255) {
            *size = 7;
        }
        memcpy(input, dst + front, *size);
    } else {
        memset(input, 0, *size);
        *size = 0;
        return;
    }
}

void dh_show_protocol_params(DH *dh) {
    BIO *b;
    b = BIO_new(BIO_s_file());
    BIO_set_fp(b, stdout, BIO_NOCLOSE);
    DHparams_print(b, dh);
    BIO_free(b);
}

void dh_show_shared_key(u_char *shared_key IN_ARG) {
    BIGNUM *temp = NULL;
    temp = BN_bin2bn(shared_key, 32, NULL);
    char *hex_key = NULL;
    hex_key = BN_bn2hex(temp);
    printf("the key is: %s\n", hex_key);
}

bool dh_set_dh_msg_item(DH_MSG *dh_msg, u_char *item, size_t item_size) {
    if (dh_msg->body.valid_length > (uint8_t) 255) {
        dh_error_handle("dh_set_dh_msg_item(): dh_msg items full");
        return false;
    }
    if (item_size > (uint8_t) 255) {
        dh_error_handle("dh_set_dh_msg_item(): item is too large");
        return false;
    }
    dh_msg->body.body_item[dh_msg->body.valid_length].item_length = item_size;
    memcpy(dh_msg->body.body_item[dh_msg->body.valid_length++].item, item, item_size);
    return true;
}

uint8_t dh_get_dh_msg_item(DH_MSG *dh_msg, size_t i, u_char *item, size_t item_size) {
    if (dh_msg->body.valid_length < (uint8_t) i) {
        dh_error_handle("dh_get_dh_msg_item(): no this item in dh_msg");
        return 0;
    }
    if (item_size < dh_msg->body.body_item[0].item_length) {
        dh_error_handle("dh_get_dh_msg_item(): buffer given is too small");
        return 0;
    }
    item_size = dh_msg->body.body_item[i].item_length;
    memcpy(item, dh_msg->body.body_item[i].item, item_size);
    return item_size;
}