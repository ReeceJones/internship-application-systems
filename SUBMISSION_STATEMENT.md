Hello Cloudflare people. I thought the project was quite fun, and I appreciate your apparent friendliness.
I've included several files: pingeroo.h, pingeroo.c, main.c, Makefile. These include various aspects of the project.
pingeroo.c and pingeroo.h contain the backend code to do the icmp, and socket stuff, whereas main.c just contains the frontend CLI stuff.
I've also included a Makefile to make it simpler to build the project.
The project is target towards a relatively modern version of linux. I didn't take note of any specific kernel versions required to run the project, but I think it'll be fine.

I wrote the project initially inteding to use C99, but function I use for host resolution required extensions, so the project uses gnu99 and builds with gcc.

Other than that, my code is relatively well documented so hopefully you don't have any trouble reading it. I also thought that the project was quite fun. I even plan on extending it a little bit so that I can use it to monitor when my servers and computers go offline.

To the best of my understanding my application does the following:
-[X] Uses C
-[X] Has a CLI Interface
-[X] Sends ICMP echo requests in an infinite loop.
-[X] Reports packet loss and echo latency for each message.
-[X] Supports IPV6. (this was harder than I expected, because it took me a while to realize that with the IPPROTO\_ICMP option on the socket, the socket will validate the ICMP format and the format for echo requests slightly differs between ipv4 and ipv6).
-[] Supports custom TLL. I had some trouble with getting this to work properly, so I decided to leave it out.-[X] Extra features: custom time delay, strict mode, force ipv4, force ipv6, use userland implementation of internet\_checksum (I think this option is useless as it gets overwritten by the kernel anyways), custom payload size

Thank you, and stay healthy

