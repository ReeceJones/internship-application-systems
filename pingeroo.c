#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#define ECHO_SIZE 64

/*
 * References
 * - https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
 * - https://www.binarytides.com/icmp-ping-flood-code-sockets-c-linux/
 * - http://man7.org/linux/man-pages/man7/raw.7.html
 * - https://linux.die.net/man/2/socket
 * - https://stackoverflow.com/questions/14774668/what-is-raw-socket-in-socket-programming
 * - http://www.rfc-editor.org/ien/ien54.pdf
 * - https://github.com/bminor/newlib/blob/master/newlib/libc/sys/linux/include/netinet/ip.h
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
    const char* server = "138.67.48.54";
    //const char* server = "127.0.0.1";
    unsigned long server_address = inet_addr(server);
    if (server_address == INADDR_NONE) {
        fprintf(stderr, "Invalid Address\n");
        return 1;
    }
    struct sockaddr_in socket_server_address = { 0 };
    socket_server_address.sin_family = AF_INET;
    socket_server_address.sin_addr.s_addr = server_address;
    socket_server_address.sin_port = htons(0);
    // create a datagram socket using ICMP protocol
    int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (socket_fd < 0) {
        fprintf(stderr, "Unable to create socket. Are you running as root?\n");
        return 1;
    }

    struct icmphdr* icmp = malloc(sizeof(struct icmphdr) + ECHO_SIZE);
    if (icmp == NULL) {
        fprintf(stderr, "Failed to allocate memory for outgoing icmp\n");
        close(socket_fd);
        return 1;
    }

    unsigned long seq = 1;
    while (1) {
        memset(icmp, 0, sizeof(struct icmphdr) + ECHO_SIZE);

        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.sequence = seq++;
        icmp->un.echo.id = getpid();
        icmp->checksum = 0;
        icmp->checksum = internet_checksum((unsigned short*)icmp,
                                           sizeof(struct icmphdr));
        int err = sendto(socket_fd, (void*)icmp, sizeof(struct icmphdr) + ECHO_SIZE,
                         0,(struct sockaddr*)&socket_server_address,
                         sizeof(struct sockaddr_in));
        if (err <= 0) {
            fprintf(stderr, "Failed to send ICMP request: %d\n", errno);
            close(socket_fd);
            free(icmp);
            return 1;
        }

        printf("Sent %d bytes\n", err);

        struct sockaddr incoming_addr = { 0 };
        socklen_t size = sizeof(struct sockaddr);
        err = recvfrom(socket_fd, icmp, sizeof(struct icmphdr) + ECHO_SIZE,
                       0, &incoming_addr, &size);
        if (err < 0) {
            fprintf(stderr, "Failed to receive ICMP message: %d\n", errno);
            close(socket_fd);
            free(icmp);
            return 1;
        }
        printf("Received %d bytes\n", err);
        printf("%d\n", icmp->type);
        
        sleep(1);
    }

    return 0;
}
