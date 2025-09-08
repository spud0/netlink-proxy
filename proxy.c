// Compile: gcc proxy.c -o proxy $(pkg-config --cflags --libs libnl-3.0)
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/netlink-compat.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <errno.h>
#include <time.h>

#define SOCKET_PATH "/tmp/nl-message.sock"
#define MAX_CLIENTS 240
#define MAX_EVENTS 20

int uds_fd;
int epfd;
int nl_fd;
int message_count = 0;
int client_fds[MAX_CLIENTS];
int num_clients = 0;

void print_timestamp() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    printf("[%ld.%03ld] ", ts.tv_sec, ts.tv_nsec / 1000000);
}

void print_hex_dump(const char *prefix, const void *data, size_t len) {
    const unsigned char *bytes = (const unsigned char *)data;
    int dump_len = (len > 64) ? 64 : len;
    
    printf("%s Raw hex dump (first %d of %zu bytes):\n", prefix, dump_len, len);
    for (int i = 0; i < dump_len; i++) {
        printf("%02x ", bytes[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (dump_len % 16 != 0) printf("\n");
}

// Remove client from epoll set and client array
void remove_client(int client_fd) {
    print_timestamp();
    printf("PROXY: Removing client fd=%d\n", client_fd);
    
    // Remove from epoll
    epoll_ctl(epfd, EPOLL_CTL_DEL, client_fd, NULL);
    close(client_fd);
    
    // Remove from client array
    for (int i = 0; i < num_clients; i++) {
        if (client_fds[i] == client_fd) {
            // Shift remaining clients down
            for (int j = i; j < num_clients - 1; j++) {
                client_fds[j] = client_fds[j + 1];
            }
            num_clients--;
            break;
        }
    }
    
    print_timestamp();
    printf("PROXY: Client removed. Active clients: %d\n", num_clients);
}

// Add new client to epoll set and client array
void add_client(int new_client_fd) {
    if (num_clients >= MAX_CLIENTS) {
        print_timestamp();
        printf("PROXY: Maximum clients reached, rejecting connection\n");
        close(new_client_fd);
        return;
    }
    
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLRDHUP;
    ev.data.fd = new_client_fd;
    
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, new_client_fd, &ev) < 0) {
        perror("PROXY: epoll_ctl ADD client failed");
        close(new_client_fd);
        return;
    }
    
    client_fds[num_clients++] = new_client_fd;
    
    print_timestamp();
    printf("PROXY: Client fd=%d added. Active clients: %d\n", new_client_fd, num_clients);
}

// Handle new client connections
void handle_new_client() {
    int new_client_fd = accept(uds_fd, NULL, NULL);
    if (new_client_fd < 0) {
        perror("PROXY: accept failed");
        return;
    }
    
    print_timestamp();
    printf("PROXY: New client connected (fd=%d)\n", new_client_fd);
    add_client(new_client_fd);
}

// Send raw netlink message buffer to all connected clients
void forward_to_client(struct nl_msg *msg) {
    if (num_clients == 0) {
        print_timestamp();
        printf("PROXY: No clients connected, dropping message\n");
        return;
    }

    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    size_t total_len = hdr->nlmsg_len;
    
    print_timestamp();
    printf("PROXY: Broadcasting netlink message to %d clients:\n", num_clients);
    printf("  Message length: %zu bytes\n", total_len);
    printf("  Message type: %u (%s)\n", hdr->nlmsg_type,
           (hdr->nlmsg_type == RTM_NEWLINK) ? "RTM_NEWLINK" :
           (hdr->nlmsg_type == RTM_DELLINK) ? "RTM_DELLINK" :
           (hdr->nlmsg_type == RTM_GETLINK) ? "RTM_GETLINK" :
           (hdr->nlmsg_type == RTM_SETLINK) ? "RTM_SETLINK" : "UNKNOWN");
    printf("  Message flags: 0x%04x\n", hdr->nlmsg_flags);
    printf("  Message seq: %u\n", hdr->nlmsg_seq);
    printf("  Message pid: %u\n", hdr->nlmsg_pid);

    // Print detailed link message info if applicable
    if (hdr->nlmsg_type == RTM_NEWLINK || hdr->nlmsg_type == RTM_DELLINK) {
        if (hdr->nlmsg_len >= NLMSG_HDRLEN + sizeof(struct ifinfomsg)) {
            struct ifinfomsg *ifi = (struct ifinfomsg *) NLMSG_DATA(hdr);
            printf("PROXY: Link Message Details:\n");
            printf("  Interface family: %u\n", ifi->ifi_family);
            printf("  Interface type: %u\n", ifi->ifi_type);
            printf("  Interface index: %d\n", ifi->ifi_index);
            printf("  Interface flags: 0x%08x (", ifi->ifi_flags);
            
            // Print flag meanings
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
            printf(")\n");
            printf("  Interface change mask: 0x%08x\n", ifi->ifi_change);
        }
    }

    print_hex_dump("PROXY: ", hdr, total_len);

    // Broadcast to all connected clients, no special dispatching right now.
    for (int i = 0; i < num_clients; i++) {
        ssize_t sent = send(client_fds[i], hdr, total_len, MSG_NOSIGNAL);
        if (sent < 0) {
            print_timestamp();
            printf("PROXY: Send failed to client fd=%d: %s\n", client_fds[i], strerror(errno));
            remove_client(client_fds[i]);
            i--; // Adjust index since array shifted
        } else {
            print_timestamp();
            printf("PROXY: Successfully sent %zd bytes to client fd=%d\n", sent, client_fds[i]);
        }
    }
}

// Netlink handler
int netlink_handler(struct nl_msg *msg, void *arg) {
    message_count++;
    
    print_timestamp();
    printf("PROXY: Received netlink message #%d from kernel\n", message_count);
    
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    if (!hdr) {
        print_timestamp();
        printf("PROXY: ERROR - hdr is NULL\n");
        return NL_SKIP;
    }

    print_timestamp();
    printf("PROXY: Kernel message details:\n");
    printf("  Length: %u bytes\n", hdr->nlmsg_len);
    printf("  Type: %u (%s)\n", hdr->nlmsg_type,
           (hdr->nlmsg_type == RTM_NEWLINK) ? "RTM_NEWLINK" :
           (hdr->nlmsg_type == RTM_DELLINK) ? "RTM_DELLINK" :
           (hdr->nlmsg_type == RTM_GETLINK) ? "RTM_GETLINK" :
           (hdr->nlmsg_type == RTM_SETLINK) ? "RTM_SETLINK" : "UNKNOWN");
    printf("  Flags: 0x%04x\n", hdr->nlmsg_flags);
    printf("  Sequence: %u\n", hdr->nlmsg_seq);
    printf("  PID: %u\n", hdr->nlmsg_pid);

    if (hdr->nlmsg_type == RTM_NEWLINK || hdr->nlmsg_type == RTM_DELLINK) {
        print_timestamp();
        printf("PROXY: This is a link message - forwarding to all clients\n");
        forward_to_client(msg);
    } else {
        print_timestamp();
        printf("PROXY: Ignoring non-link message type %u\n", hdr->nlmsg_type);
    }
    
    fflush(stdout);
    return NL_OK;
}

int main() {
    print_timestamp();
    printf("PROXY: Starting netlink proxy server...\n");
    
    // Initialize client array
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_fds[i] = -1;
    }
    
    // Set up Unix Domain Socket
    struct sockaddr_un addr;
    uds_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (uds_fd < 0) {
        perror("PROXY: socket creation failed");
        exit(1);
    }

    unlink(SOCKET_PATH);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(uds_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("PROXY: bind failed");
        exit(1);
    }

    if (listen(uds_fd, 5) < 0) {
        perror("PROXY: listen failed");
        exit(1);
    }

    print_timestamp();
    printf("PROXY: Unix domain socket listening on %s\n", SOCKET_PATH);

    // Set up Netlink socket
    struct nl_sock *nl = nl_socket_alloc();
    if (!nl) {
        fprintf(stderr, "PROXY: Failed to allocate netlink socket\n");
        exit(1);
    }
    
    print_timestamp();
    printf("PROXY: Configuring netlink socket...\n");
    
    nl_socket_disable_seq_check(nl);
    nl_socket_modify_cb(nl, NL_CB_VALID, NL_CB_CUSTOM, netlink_handler, NULL);

    if (nl_connect(nl, NETLINK_ROUTE) != 0) {
        fprintf(stderr, "PROXY: Failed to connect netlink socket\n");
        exit(1);
    }

    print_timestamp();
    printf("PROXY: Connected to NETLINK_ROUTE\n");

    if (nl_socket_add_membership(nl, RTNLGRP_LINK) < 0) {
        fprintf(stderr, "PROXY: Failed to join RTNLGRP_LINK group\n");
        exit(1);
    }

    print_timestamp();
    printf("PROXY: Joined RTNLGRP_LINK multicast group\n");

    // Get netlink file descriptor for epoll
    nl_fd = nl_socket_get_fd(nl);
    
    // Create epoll instance
    epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("PROXY: epoll_create1 failed");
        exit(1);
    }
    
    print_timestamp();
    printf("PROXY: Created epoll instance\n");

    // Add UDS server socket to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = uds_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, uds_fd, &ev) < 0) {
        perror("PROXY: epoll_ctl ADD uds_fd failed");
        exit(1);
    }

    // Add netlink socket to epoll
    ev.data.fd = nl_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, nl_fd, &ev) < 0) {
        perror("PROXY: epoll_ctl ADD nl_fd failed");
        exit(1);
    }

    print_timestamp();
    printf("PROXY: Added sockets to epoll (UDS fd=%d, Netlink fd=%d)\n", uds_fd, nl_fd);
    printf("PROXY: Ready to receive RTM_NEWLINK and RTM_DELLINK messages\n");
    printf("PROXY: Waiting for client connections and netlink events...\n");
    fflush(stdout);

    struct epoll_event events[MAX_EVENTS];
    
    while (1) {
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            perror("PROXY: epoll_wait failed");
            continue;
        }
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == uds_fd) {
                // New client connection
                print_timestamp();
                printf("PROXY: New client connection detected\n");
                handle_new_client();
            } else if (events[i].data.fd == nl_fd) {
                // Netlink message received
                print_timestamp();
                printf("PROXY: Netlink message detected\n");
                int ret = nl_recvmsgs_default(nl);
                if (ret < 0) {
                    print_timestamp();
                    printf("PROXY: nl_recvmsgs_default returned %d\n", ret);
                }
            } else {
                // Client socket event (likely disconnection)
				// Close, Hangup or Error
                if (events[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
                    print_timestamp();
                    printf("PROXY: Client fd=%d disconnected\n", events[i].data.fd);
                    remove_client(events[i].data.fd);
                }
            }
        }
    }

    // Cleanup
    for (int i = 0; i < num_clients; i++) {
        close(client_fds[i]);
    }

    close(epfd);
    nl_socket_free(nl);
    close(uds_fd);
    unlink(SOCKET_PATH);
    return 0;
}
