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
    unsigned short sum = 0;
    for (int i = 0; i < len / 2; i++) {
        sum += ~data[i];
    }
    return ~sum;
}

int main(int argc, char** argv) {
    const char* server = "127.0.0.1";
    unsigned long server_address = inet_addr(server);
    if (server_address == INADDR_NONE) {
        fprintf(stderr, "Invalid Address\n");
        return 1;
    }
    struct sockaddr_in socket_server_address = { 0 };
    socket_server_address.sin_family = AF_INET;
    socket_server_address.sin_addr.s_addr = server_address;
    // raw socket so we can access icmp stuffz
    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (socket_fd < 0) {
        fprintf(stderr, "Unable to create socket\n");
        return 1;
    }
    int buf = 1;
    // provide our own IP headers
    int err = setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &buf, sizeof(int));
    if (err < 0) {
        fprintf(stderr, "Unable to set socket option IP_HDR_INCL\n");
        return 1;
    }
    // use datagrams
    err = setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, &buf, sizeof(int));
    if (err <  0) {
        fprintf(stderr, "Unable to set socket option SO_BROADCAST\n");
        return 1;
    }

    err = bind(socket_fd, (struct sockaddr*)&socket_server_address, sizeof(struct sockaddr_in));
    if (err != 0) {
        printf("Failed to bind socket: %d\n", errno);
        close(socket_fd);
        return 1;
    }

    // allocate some memory for the outgoing packets.
    const int packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + ECHO_SIZE;
    void* outgoing_packet = malloc(packet_size);
    if (outgoing_packet == NULL) {
        fprintf(stderr, "Failed to allocate memory for outgoing packets\n");
        return 1;
    }

    // allocate some memory for incoming packets (ECHO_REPLY)
    // We read the echo data after we receive the IP and ICMP headers
    void* incoming_packet = malloc(packet_size - ECHO_SIZE);
    if (incoming_packet == NULL) {
        fprintf(stderr, "Failed to allocate memory for incoming packet\n");
        return 1;
    }

    memset(outgoing_packet, 0, packet_size);

    struct iphdr* outgoing_ip = (struct iphdr*)outgoing_packet;
    struct icmphdr* outgoing_icmp = (struct icmphdr*)(outgoing_packet + sizeof(struct iphdr));

    struct iphdr* incoming_ip = (struct iphdr*)incoming_packet;
    struct icmphdr* incoming_icmp = (struct icmphdr*)(incoming_packet + sizeof(struct iphdr));

    outgoing_ip->version = 4; // IPV4
    outgoing_ip->ihl = 5; // header length
    outgoing_ip->tos = 0; // type of service (0 because we are dealing with datagrams)
    outgoing_ip->tot_len = htons(packet_size); // Set the total length of our message
    outgoing_ip->id = 0x00; // Our id. Not sure about this one.
    outgoing_ip->frag_off = 0; // Set fragmentation offset to 0
    outgoing_ip->ttl = 55; // set time-to-live (seconds)
    outgoing_ip->protocol = IPPROTO_ICMP; // We are doing ICMP protocol
    outgoing_ip->saddr = (unsigned int)inet_addr("73.192.144.165"); // Set the source address (us)
    outgoing_ip->daddr = (unsigned int)server_address; // Set the target addr
    outgoing_ip->check = internet_checksum((unsigned short*)&outgoing_ip, sizeof(struct iphdr));

    outgoing_icmp->type = ICMP_ECHO;
    outgoing_icmp->code = 0;
    outgoing_icmp->un.echo.sequence = 1;
    outgoing_icmp->un.echo.id = 7;
    outgoing_icmp->checksum = internet_checksum((unsigned short*)&outgoing_icmp, sizeof(struct icmphdr));

    while (1) {
        printf("ping-pong\n");
        err = sendto(socket_fd, outgoing_packet, packet_size, 0,
               (struct sockaddr*)&socket_server_address, sizeof(struct sockaddr_in));
        if (err <= 0) {
            fprintf(stderr, "Failed to send ICMP message: %d\n", errno);
            free(outgoing_packet);
            free(incoming_packet);
            close(socket_fd);
            return 1;
        }
        printf("Sent %d byes\n", err);
        unsigned long sock_addr_len = sizeof(struct sockaddr_in);
        err = recvfrom(socket_fd, incoming_packet, packet_size - ECHO_SIZE - sizeof(struct icmphdr), 0,
                       (struct sockaddr*)&socket_server_address, (socklen_t*)&sock_addr_len);
        if (err <= 0) {
            fprintf(stderr, "Failed to receive ICMP message: %d\n", errno);
            free(outgoing_packet);
            free(incoming_packet);
            close(socket_fd);
            return 1;
        }
        printf("Received %d bytes\n", err);
        printf("%d %d\n", incoming_ip->tot_len, incoming_icmp->code);

        outgoing_icmp->un.echo.sequence++;
        sleep(1);
    }
    
    return 0;
}
