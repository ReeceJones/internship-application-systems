#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>

#include "pingeroo.h"

int main(int argc, char** argv) {
    if (argc <= 1) {
        fprintf(stderr, "Expected more arguments\n");
        return 1;
    }
    
    int ip_mode = -1;
    int strict_recv = 0;
    int local_check = 0;
    unsigned long payload_size = 64;
    int opt = 0;
    unsigned long delay = 1000;
    while ((opt = getopt(argc, argv, "46csp:d:h")) != -1) {
        switch (opt) {
            default:
            case  '?':
                fprintf(stderr, "Unknown option\n");
                return 1;
            case '4':
                if (ip_mode == -1 || ip_mode == AF_INET) {
                    ip_mode = AF_INET;
                }
                else {
                    fprintf(stderr, "Option 4 conflicts with 6\n");
                    return 1;
                }
            break;
            case '6':
                if (ip_mode == -1 || ip_mode == AF_INET6) {
                    ip_mode = AF_INET6;
                }
                else {
                    fprintf(stderr, "Option 6 conflicts with 4\n");
                    return 1;  
                }
            break;
            case 'c':
                local_check = 1;
            break;
            case 's':
                strict_recv = 1;
            break;
            case 'p':
                payload_size = atol(optarg);
            break;
            case 'd':
                delay = atol(optarg);
            break;
            case 'h':
                printf("Usage: pingeroo [options] <hostname or ip address>\n"
                       "\t-h - Display this page\n"
                       "\t-4 - Use ipv4 only\n"
                       "\t-6 - Use ipv6 only\n"
                       "\t-c - Manually calculate checksum (Likely useless)\n"
                       "\t-s - Strict packet drop mode. If the number of packets received isn't the same as the number of packets sent, that sequence is considered dropped\n"
                       "\t-p <size> - Specify a custom payload size for ping request\n"
                       "\t-d <ms> - Specify a delay between pings in milliseconds.\n");
            break;
        }
    }

    if (optind >= argc || optind < argc - 1) {
        fprintf(stderr, "Bad arguments: use -h to see options\n");
        return 1;
    }

    const char* server = (const char*)argv[optind];
    return do_ping(server, ip_mode, local_check, strict_recv, payload_size, delay);
}
