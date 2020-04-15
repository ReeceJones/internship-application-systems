#pragma once

#include <netdb.h>

/// Calculates an internet checksum. Supposedly the kernel will autocalculate this for us
/// as we use IPPROTO_ICMP(V6) so this is likely useless.
unsigned short internet_checksum(unsigned short*, unsigned int);

/// Takes in a host (ip or hostname) and gives back a usable addrinfo structure containing matches.
int resolve_host(const char*, struct addrinfo**);

/// Extracts usable sockaddr from addrinfo structure.
int get_sockaddr(struct addrinfo*, int*, struct sockaddr**, socklen_t*);

/// Converts a sock addr to an ip string like "127.0.0.01", "::1", etc.
char* get_ipstr(struct sockaddr*, int ip_mode);

/// Allocate space for an icmp structure.
void* icmp_malloc(int, unsigned long, unsigned int*);

/// Initialize an icmp structure. This is called every ping to clear out response data.
void icmp_init(void*, unsigned int, int, int, int);

/// Infinite loop that does an icmp ping.
int icmp_ping(const char*, const char*, struct sockaddr*,
              socklen_t, int, int, int, int, unsigned long, unsigned long);

/// Does an icmp ping given a host and some options.
int do_ping(const char*, int, int, int, unsigned long, unsigned long);

