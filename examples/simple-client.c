// Compile: gcc simple-client.c -o client $(pkg-config --cflags --libs libnl-3.0)
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/nl-message.sock"

int main() {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    printf("=== CLIENT: Connected to proxy, waiting for netlink messages ===\n");
    
    int message_count = 0;
    while (1) {
        char buf[4096];  // Store the netlink message here.
        int len = recv(sock, buf, sizeof(buf), 0);
        if (len <= 0) {
            if (len == 0) {
                printf("CLIENT: Server closed connection\n");
            } else {
                perror("recv");
            }
            break;
        }

        message_count++;
        printf("\n=== CLIENT: Message #%d ===\n", message_count);
        printf("CLIENT: Received %d bytes from proxy\n", len);

        // Cast buf directly to nlmsghdr
        struct nlmsghdr *hdr = (struct nlmsghdr *)buf;
        
        // Validate the message
        if (len < sizeof(struct nlmsghdr) || hdr->nlmsg_len > len) {
            fprintf(stderr, "CLIENT: Invalid netlink message received\n");
            continue;
        }

        // Print detailed netlink header information
        printf("CLIENT: Netlink Header Details:\n");
        printf("  nlmsg_len: %u bytes\n", hdr->nlmsg_len);
        printf("  nlmsg_type: %u (%s)\n", hdr->nlmsg_type,
               (hdr->nlmsg_type == RTM_NEWLINK) ? "RTM_NEWLINK" :
               (hdr->nlmsg_type == RTM_DELLINK) ? "RTM_DELLINK" : "UNKNOWN");
        printf("  nlmsg_flags: 0x%04x\n", hdr->nlmsg_flags);
        printf("  nlmsg_seq: %u\n", hdr->nlmsg_seq);
        printf("  nlmsg_pid: %u\n", hdr->nlmsg_pid);

        // Print raw hex dump of first 64 bytes (or entire message if smaller)
        int dump_len = (len > 64) ? 64 : len;
        printf("CLIENT: Raw hex dump (first %d bytes):\n", dump_len);
        for (int i = 0; i < dump_len; i++) {
            printf("%02x ", (unsigned char)buf[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        if (dump_len % 16 != 0) printf("\n");

        // If it's a link message, try to parse some basic info
        if (hdr->nlmsg_type == RTM_NEWLINK || hdr->nlmsg_type == RTM_DELLINK) {
            if (hdr->nlmsg_len >= NLMSG_HDRLEN + sizeof(struct ifinfomsg)) {
                struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(hdr);
                printf("CLIENT: Link Message Details:\n");
                printf("  Interface family: %u\n", ifi->ifi_family);
                printf("  Interface type: %u\n", ifi->ifi_type);
                printf("  Interface index: %d\n", ifi->ifi_index);
                printf("  Interface flags: 0x%08x\n", ifi->ifi_flags);
                printf("  Interface change mask: 0x%08x\n", ifi->ifi_change);
                
                // Print flag meanings
                printf("  Flags: ");
                if (ifi->ifi_flags & IFF_UP) printf("UP ");
                if (ifi->ifi_flags & IFF_BROADCAST) printf("BROADCAST ");
                if (ifi->ifi_flags & IFF_DEBUG) printf("DEBUG ");
                if (ifi->ifi_flags & IFF_LOOPBACK) printf("LOOPBACK ");
                if (ifi->ifi_flags & IFF_POINTOPOINT) printf("POINTOPOINT ");
                if (ifi->ifi_flags & IFF_RUNNING) printf("RUNNING ");
                if (ifi->ifi_flags & IFF_NOARP) printf("NOARP ");
                if (ifi->ifi_flags & IFF_PROMISC) printf("PROMISC ");
                if (ifi->ifi_flags & IFF_ALLMULTI) printf("ALLMULTI ");
                if (ifi->ifi_flags & IFF_MULTICAST) printf("MULTICAST ");
                printf("\n");
            }
        }

        printf("CLIENT: Processed message #%d\n", message_count);
        fflush(stdout);
    }

    close(sock);
    return 0;
}

