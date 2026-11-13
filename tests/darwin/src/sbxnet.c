// Sandbox's socket checks. Unsandboxed, the platform profile allows an
// inet socket's bind and listen. Under nointernet an inet socket may be
// made (socket_check_create asks nothing of an inet stream or datagram
// socket) and its options set, but not bound, connected or sent from:
// its network-bind, network-inbound and network-outbound match any inet
// local address, an unbound socket's 0.0.0.0 among them. A unix socket's
// operations are allowed at once, whatever the profile.

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SANDBOX_NAMED_BUILTIN 2

int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);

static int fail(const char *what, long got) {
    printf("sbxnet: %s: %ld\n", what, got);
    return 1;
}

static struct sockaddr_in loopback(in_port_t port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_len = sizeof a;
    a.sin_family = AF_INET;
    a.sin_port = port;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return fail("socket", errno);
    struct sockaddr_in a = loopback(0);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) return fail("bind before", errno);
    if (listen(s, 1) != 0) return fail("listen before", errno);
    socklen_t len = sizeof a;
    if (getsockname(s, (struct sockaddr *)&a, &len) != 0) return fail("getsockname", errno);
    char *err = NULL;
    if (sandbox_init("nointernet", SANDBOX_NAMED_BUILTIN, &err) != 0) return fail("sandbox_init", errno);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0) return fail("socket in the sandbox", errno);
    int one = 1;
    if (setsockopt(c, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) return fail("setsockopt", errno);
    if (connect(c, (struct sockaddr *)&a, sizeof a) != -1 || errno != EPERM) return fail("connect", errno);
    int d = socket(AF_INET, SOCK_DGRAM, 0);
    if (d < 0) return fail("datagram socket", errno);
    struct sockaddr_in any = loopback(0);
    if (bind(d, (struct sockaddr *)&any, sizeof any) != -1 || errno != EPERM) return fail("bind", errno);
    if (sendto(d, "x", 1, 0, (struct sockaddr *)&a, sizeof a) != -1 || errno != EPERM) return fail("sendto", errno);
    if (listen(c, 1) != -1 || errno != EPERM) return fail("listen", errno);
    int sv[2];
    char ch = 0;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return fail("socketpair", errno);
    if (write(sv[0], "u", 1) != 1 || read(sv[1], &ch, 1) != 1 || ch != 'u') return fail("unix socket", errno);
    printf("sbxnet ok\n");
    return 0;
}
