#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

/*
 * References:
 * - https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
 * - https://www.binarytides.com/icmp-ping-flood-code-sockets-c-linux/
 * - http://man7.org/linux/man-pages/man7/raw.7.html
 * - https://linux.die.net/man/2/socket
 * - https://stackoverflow.com/questions/14774668/what-is-raw-socket-in-socket-programming
 * - http://www.rfc-editor.org/ien/ien54.pdf
 * - https://github.com/bminor/newlib/blob/master/newlib/libc/sys/linux/include/netinet/ip.h
 * - https://en.wikipedia.org/wiki/Ping_(networking_utility)#Echo_request
 */

unsigned short internet_checksum(unsigned short* data, unsigned int len) {
    unsigned int sum = 0;
    for (sum = 0; len > 1; len -= 2) {
        sum += *data++;
    }
    if (len == 1) {
        sum += *(unsigned char*)data;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

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
    while ((opt = getopt(argc, argv, "46csp:h")) != -1) {
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
                payload_size = atoi(optarg);
            break;
            case 'h':
                printf("Usage: pingeroo [options] <hostname or ip address>\n"
                       "\t-h - Display this page\n"
                       "\t-4 - Use ipv4 only\n"
                       "\t-6 - Use ipv6 only\n"
                       "\t-c - Manually calculate checksum (Likely useless)\n"
                       "\t-s - Strict packet drop mode. If the number of packets received isn't the same as the number of packets sent, that sequence is considered dropped\n"
                       "\t-p <size> - Specify a custom payload size for ping request\n");                
            break;
        }
    }

    if (optind >= argc || optind < argc - 1) {
        fprintf(stderr, "Bad arguments: use -h to see options\n");
        return 1;
    }

    const char* server = (const char*)argv[optind];

    // Resolve host location
    struct addrinfo hints = { 0 };
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo* hits;
    int err = getaddrinfo(server, NULL, &hints, &hits);

    if (err != 0) {
        fprintf(stderr, "Could not resolve hostname!"
                        " Make sure you entered a valid IP/hostname.\n");
        return 1;
    }

    struct addrinfo* node = hits;

    socklen_t socket_len = 0; // hits->ai_addrlen;
    struct sockaddr* socket_server_address = NULL; // hits->ai_addr;
    if (ip_mode != -1) {
        while (node != NULL) {
            if (node->ai_family == ip_mode) {
                socket_len = node->ai_addrlen;
                socket_server_address = node->ai_addr;
                break;
            }
            node = node->ai_next;
        }
        if (node == NULL) {
            fprintf(stderr, "Could not find host ip that matched requirement: %s\n",
                    ip_mode == AF_INET ? "ipv4" : "ipv6");
            freeaddrinfo(hits);
            return 1;
        }
    }
    else {
        ip_mode = hits->ai_family;
        socket_len = hits->ai_addrlen;
        socket_server_address = hits->ai_addr;
    }

    char* resolved = malloc(0xff);
    if (ip_mode == AF_INET) {
        inet_ntop(node->ai_family, &(((struct sockaddr_in*)node->ai_addr)->sin_addr), resolved, 0xff);
    }
    else {
        inet_ntop(node->ai_family, &(((struct sockaddr_in6*)node->ai_addr)->sin6_addr), resolved, 0xff);
    }

    int protocol = ip_mode == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6;

    // create a datagram socket using ICMP protocol
    int socket_fd = socket(ip_mode, SOCK_DGRAM, protocol);
    if (socket_fd < 0) {
        fprintf(stderr, "Unable to create socket: %d.\n", errno);
        freeaddrinfo(hits);
        free(resolved);
        return 1;
    }

    unsigned int icmp_size = ip_mode == AF_INET ? sizeof(struct icmphdr)
                             : sizeof(struct icmp6_hdr);
    icmp_size += payload_size;

    void* icmp_blob = malloc(icmp_size);
    if (icmp_blob == NULL) {
        fprintf(stderr, "Failed to allocate memory for outgoing icmp\n");
        close(socket_fd);
        freeaddrinfo(hits);
        free(resolved);
        return 1;
    }

    unsigned long seq = 1;
    unsigned long dropped = 0;
    while (1) {
        memset(icmp_blob, 0, icmp_size);

        if (ip_mode == AF_INET) {
            struct icmphdr* icmp = (struct icmphdr*)icmp_blob;
            icmp->type = ICMP_ECHO;
            icmp->code = 0;
            icmp->un.echo.sequence = seq;
            icmp->un.echo.id = getpid();
            icmp->checksum = 0;
            if (local_check) {
                icmp->checksum = internet_checksum((unsigned short*)icmp_blob, icmp_size);
            }
        }
        else {
            struct icmp6_hdr* icmp6 = (struct icmp6_hdr*)icmp_blob;
            icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
            icmp6->icmp6_code = 0;
            icmp6->icmp6_dataun.icmp6_un_data16[0] = getpid();
            icmp6->icmp6_dataun.icmp6_un_data16[1] = seq;
            icmp6->icmp6_cksum = 0;
            if (local_check) {
                icmp6->icmp6_cksum = internet_checksum((unsigned short*)icmp_blob, icmp_size);
            }
        }
        err = sendto(socket_fd, icmp_blob, icmp_size, 0, socket_server_address, socket_len);
        if (err <= 0) {
            fprintf(stderr, "Failed to send ICMP request: %d\n", errno);
            // Failed to send packet. Likely an issue on our end, so just continue.
            sleep(1);
            continue;
        }

        int sent = err;

        struct sockaddr incoming_addr = { 0 };
        socklen_t size = socket_len;
        err = recvfrom(socket_fd, icmp_blob, icmp_size, 0, &incoming_addr, &size);
        if (err <= 0) {
            fprintf(stderr, "Failed to receive ICMP message: %d\n", errno);
            // If we didn't hear a response, that likely means the packet didn't make it.
            dropped++;
        }
        else {
            if (strict_recv && sent != err) {
                printf("(Data length mismatch: sent: %d recv: %d) ", sent, err);
                dropped++;
            }
            printf("%d bytes received from %s -> %s; "
                   "icmp_seq=%ld time=%.4f dropped=%ld\\%ld\n",
                    err, server, resolved, seq, 1.0f, dropped, seq);
        }
        
        seq++;
        sleep(1);
    }

    free(icmp_blob);
    free(resolved);
    freeaddrinfo(hits);

    return 0;
}
