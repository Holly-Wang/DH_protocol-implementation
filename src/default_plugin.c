//
// Created by bing on 2021/7/22.
//


#include <stdio.h>
#include <stdlib.h>

const char *plugin_desc() {
    return "default plugin";
}


void plugin_func(unsigned char *tcp_data, unsigned int data_size) {
    puts("function plugin_func() called!");
    for (int i = 0; i < data_size; ++i) {
        if ((tcp_data[i] >= 'a' && tcp_data[i] <= 'z') ||
            (tcp_data[i] >= 'A' && tcp_data[i] <= 'Z')) {
            tcp_data[i] ^= 0x20;
        }
    }
}