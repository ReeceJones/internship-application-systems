#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
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
 * - https://www.geeksforgeeks.org/ping-in-c/
 * - Various linux man pages
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

int resolve_host(const char* server, struct addrinfo** hits) {
    // Resolve host location
    struct addrinfo hints = { 0 };
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    // getaddrinfo() non-standard, requires -std=gnuXX to use.
    // unfortunately getaddrinfo() alternatives are obsolete.
    int err = getaddrinfo(server, NULL, &hints, hits);

    if (err != 0) {
        fprintf(stderr, "Could not resolve hostname!"
                        " Make sure you entered a valid IP/hostname.\n");
        return 1;
    }
    return 0;
}

int get_sockaddr(struct addrinfo* hits, int* ip_mode, struct sockaddr** socket_server_address,
                 socklen_t* socket_len) {
    struct addrinfo* node = hits;

    // iterate through linked list until we find an addr that matches our requirements
    if (*ip_mode != -1) {
        while (node != NULL) {
            if (node->ai_family == *ip_mode) {
                *socket_len = node->ai_addrlen;
                *socket_server_address = node->ai_addr;
                break;
            }
            node = node->ai_next;
        }
        if (node == NULL) {
            fprintf(stderr, "Could not find host ip that matched requirement: %s\n",
                    *ip_mode == AF_INET ? "ipv4" : "ipv6");
            freeaddrinfo(hits);
            return 1;
        }
    }
    else {
        // If user didn't specify requirements, just take first addr.
        *ip_mode = hits->ai_family;
        *socket_len = hits->ai_addrlen;
        *socket_server_address = hits->ai_addr;
    }
    return 0;
}

char* get_ipstr(struct sockaddr* socket_server_address, int ip_mode) {
    char* resolved = malloc(0xff); // 0xff should be enough for ip size.
    if (ip_mode == AF_INET) {
        inet_ntop(ip_mode, &(((struct sockaddr_in*)socket_server_address)->sin_addr), resolved, 0xff);
    }
    else {
        inet_ntop(ip_mode, &(((struct sockaddr_in6*)socket_server_address)->sin6_addr), resolved, 0xff);
    }
    return resolved;
}

void* icmp_malloc(int ip_mode, unsigned long payload_size, unsigned int* icmp_size) {
    // icmp header size may vary depending on ipv4 or ipv6.
    *icmp_size = ip_mode == AF_INET ? sizeof(struct icmphdr)
                             : sizeof(struct icmp6_hdr);
    *icmp_size += payload_size; // junk data after the header.

    void* icmp_blob = malloc(*icmp_size);
    if (icmp_blob == NULL) {
        fprintf(stderr, "Failed to allocate memory for outgoing icmp\n");
        return NULL;
    }

    return icmp_blob;
}

void icmp_init(void* icmp_blob, unsigned int icmp_size, int ip_mode, int seq, int local_check) {
    memset(icmp_blob, 0, icmp_size);

    // icmp header uses a different structure and #defines depending on ipv4 or ipv6
    // not using the respective structs/#defines may cause errno 22 on sendto()

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
        icmp6->icmp6_dataun.icmp6_un_data16[0] = getpid(); // first 16 bits = id
        icmp6->icmp6_dataun.icmp6_un_data16[1] = seq; // second 16 bits = sequence
        icmp6->icmp6_cksum = 0;
        if (local_check) {
            icmp6->icmp6_cksum = internet_checksum((unsigned short*)icmp_blob, icmp_size);
        }
    }
}

int icmp_ping(const char* server, const char* resolved, struct sockaddr* socket_server_address,
              socklen_t socket_len, int ip_mode, int socket_fd, int local_check, int strict_recv,
              unsigned long payload_size, unsigned long delay) {
    // allocate our icmp packet
    unsigned int icmp_size = 0;
    void* icmp_blob = icmp_malloc(ip_mode, payload_size, &icmp_size);
    if (icmp_blob == NULL) {
        return 1;
    }

    // packet info
    unsigned long seq = 1;
    unsigned long dropped = 0;
    // some clocks
    struct timespec send_time = { 0 };
    struct timespec recv_time = { 0 };
    while (1) {
        // re-init our icmp packet
        icmp_init(icmp_blob, icmp_size, ip_mode, seq, local_check);

        // send packet
        int err = sendto(socket_fd, icmp_blob, icmp_size, 0, socket_server_address, socket_len);
        if (err <= 0) {
            fprintf(stderr, "Failed to send ICMP request: %d\n", errno);
            // Failed to send packet. Likely an issue on our end, so just continue.
            sleep(1);
            continue;
        }
        // number of bytes sent
        int sent = err;

        // read send time
        err = clock_gettime(CLOCK_MONOTONIC, &send_time);
        if (err != 0) {
            fprintf(stderr, "Failed to get clock time: %d\n", errno);
            sleep(1);
            continue;
        }

        // dummy information for incoming icmp packet
        struct sockaddr incoming_addr = { 0 };
        socklen_t size = socket_len;

        // receive icmp packet
        err = recvfrom(socket_fd, icmp_blob, icmp_size, 0, &incoming_addr, &size);
        if (err <= 0) {
            fprintf(stderr, "Failed to receive ICMP message: %d\n", errno);
            // If we didn't hear a response, that likely means the packet didn't make it.
            dropped++;
        }
        else {
            // number of bytes received
            int recv = err;

            if (strict_recv && sent != recv) {
                printf("(Data length mismatch: sent: %d recv: %d) ", sent, recv);
                dropped++;
            }

            // get received time
            err = clock_gettime(CLOCK_MONOTONIC, &recv_time);
            if (err != 0) {
                fprintf(stderr, "Failed to get clock time: %d\n", errno);
                sleep(1);
                continue;
            }

            // print info
            printf("%d bytes received from %s -> %s; "
                   "icmp_seq=%ld time=%.4fms dropped=%ld\\%ld\n",
                    recv, server, resolved, seq,
                    (double)(recv_time.tv_sec - send_time.tv_sec) * 1000.0
                    + (double)(recv_time.tv_nsec - send_time.tv_nsec) / 1000000.0, dropped, seq);
        }
        
        // increment sequence and wait some time
        seq++;
        usleep(delay * 1000);
    }

    free(icmp_blob);
    return 0;
}

int do_ping(const char* server, int ip_mode, int local_check, int strict_recv, unsigned long payload_size,
            unsigned long delay) {
    // resolve host
    struct addrinfo* hits = NULL;
    int err = resolve_host(server, &hits);
    if (err != 0) {
        return 1;
    }

    socklen_t socket_len = 0;
    struct sockaddr* socket_server_address = NULL;

    // get the sockaddr structure out of the resolved host
    err = get_sockaddr(hits, &ip_mode, &socket_server_address, &socket_len);
    if (err != 0) {
        return err;
    }

    // get the string representation of the ip
    char* resolved = get_ipstr(socket_server_address, ip_mode);

    // Make sure we are using right ICMP protocol
    int protocol = ip_mode == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6;

    // create a datagram socket using ICMP protocol
    int socket_fd = socket(ip_mode, SOCK_DGRAM, protocol);
    if (socket_fd < 0) {
        fprintf(stderr, "Unable to create socket: %d.\n", errno);
        freeaddrinfo(hits);
        free(resolved);
        return 1;
    }

    // do the actual ping loop
    err = icmp_ping(server, resolved, socket_server_address, socket_len, ip_mode, socket_fd,
                    local_check, strict_recv, payload_size, delay);

    free(resolved);
    freeaddrinfo(hits);
    return 0;
}

