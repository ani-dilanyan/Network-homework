/* End-to-end integrity test.
 *
 *   server (on PC2):  ./bin/echo_test server 8080
 *   client (on PC1):  ./bin/echo_test client 10.0.2.2 8080 [rounds]
 *
 * The client sends random messages of many sizes (including > MSS, so TCP
 * splits them into several segments); the server echoes them back and the
 * client compares every byte. Exit code 0 = all data intact.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

static int send_all(int fd, const void *b, size_t n)
{
    const uint8_t *p = b;
    while (n) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w; n -= (size_t)w;
    }
    return 0;
}

static int recv_exact(int fd, void *b, size_t n)
{
    uint8_t *p = b;
    while (n) {
        ssize_t r = recv(fd, p, n, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}

static int server(int port)
{
    int one = 1, srv = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                             .sin_addr.s_addr = htonl(INADDR_ANY)};
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(srv, (struct sockaddr *)&sa, sizeof sa) || listen(srv, 5)) {
        perror("bind/listen");
        return 1;
    }
    printf("echo server listening on %d\n", port);
    fflush(stdout);
    static uint8_t buf[1 << 17];
    for (;;) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) continue;
        uint32_t n;
        while (recv_exact(fd, &n, 4) == 0) {
            uint32_t len = ntohl(n);
            if (len > sizeof buf || recv_exact(fd, buf, len) ||
                send_all(fd, &n, 4) || send_all(fd, buf, len))
                break;
        }
        close(fd);
    }
}

static int client(const char *host, int port, int rounds)
{
    static const size_t sizes[] = {1, 15, 100, 1000, 1360, 1400, 5000, 65536};
    static uint8_t msg[65536], echo[65536];
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    inet_pton(AF_INET, host, &sa.sin_addr);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa)) {
        perror("connect");
        return 1;
    }
    unsigned long total = 0;
    for (int i = 0; i < rounds; i++) {
        size_t len = sizes[i % (int)(sizeof sizes / sizeof *sizes)];
        if (getrandom(msg, len, 0) != (ssize_t)len) return 1;
        uint32_t n = htonl((uint32_t)len), back;
        if (send_all(fd, &n, 4) || send_all(fd, msg, len) ||
            recv_exact(fd, &back, 4) || ntohl(back) != len ||
            recv_exact(fd, echo, len)) {
            printf("FAILED: connection error in round %d\n", i);
            return 1;
        }
        if (memcmp(msg, echo, len) != 0) {
            printf("MISMATCH in round %d\n", i);
            return 1;
        }
        total += len;
    }
    close(fd);
    printf("OK: %d messages, %lu bytes echoed intact\n", rounds, total);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 3 && !strcmp(argv[1], "server"))
        return server(atoi(argv[2]));
    if (argc >= 4 && !strcmp(argv[1], "client"))
        return client(argv[2], atoi(argv[3]), argc >= 5 ? atoi(argv[4]) : 40);
    fprintf(stderr, "usage: %s server PORT | client HOST PORT [ROUNDS]\n", argv[0]);
    return 2;
}
