cmake_minimum_required(VERSION 3.16)
project(diffie_hellman C)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

set(CMAKE_C_STANDARD 99)

link_directories(/usr/lib/x86_64-linux-gnu)

# server
add_executable(server main.c src/main.h src/dh_protocol.c src/dh_protocol.h src/dh_comm.c src/dh_comm.h)
target_link_libraries(server -lcrypto -lpcap -lssl -lpthread)
target_compile_options(server PRIVATE -DNORMAL_COMM_MODE -DSERVER)
# client
add_executable(client main.c src/main.h src/dh_protocol.c src/dh_protocol.h src/dh_comm.c src/dh_comm.h)
target_link_libraries(client -lcrypto -lpcap -lssl -lpthread)
target_compile_options(client PRIVATE -DNORMAL_COMM_MODE -DCLIENT)

# arp_spoof
add_executable(arp_spoof main.c src/main.h src/arpspoof.h src/arpspoof.c)
target_link_libraries(arp_spoof -lcrypto -lpcap -lssl)
target_compile_options(arp_spoof PRIVATE -DARP_SPOOF_MODE)
# man_in_middle
add_executable(man_in_middle main.c src/main.h
        src/man_in_middle.c src/man_in_middle.h
        src/dh_protocol.c src/dh_protocol.h
        )
target_link_libraries(man_in_middle -lcrypto -lpcap -lssl -ldl)
target_compile_options(man_in_middle PRIVATE -DMAN_IN_MIDDLE_MODE)

# server_safe
add_executable(server_safe main.c src/main.h src/dh_protocol.c src/dh_protocol.h src/dh_comm.c src/dh_comm.h)
target_link_libraries(server_safe -lcrypto -lpcap -lssl -lpthread)
target_compile_options(server_safe PRIVATE -DNORMAL_COMM_MODE -DSERVER -DUSE_PSK)

# server_safe
add_executable(client_safe main.c src/main.h src/dh_protocol.c src/dh_protocol.h src/dh_comm.c src/dh_comm.h)
target_link_libraries(client_safe -lcrypto -lpcap -lssl -lpthread)
target_compile_options(client_safe PRIVATE -DNORMAL_COMM_MODE -DCLIENT -DUSE_PSK)


add_library(man_in_middle_plugin SHARED src/default_plugin.c)
INSTALL(TARGETS man_in_middle_plugin LIBRARY DESTINATION ${PROJECT_BINARY_DIR}/lib)