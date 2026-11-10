// The refusals of the socket layer, in the numbers uipc_socket.c and
// uipc_syscalls.c give them: Darwin's EOPNOTSUPP is not its ENOTSUP.

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("sockerr: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int expect(const char *what, long r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

int main(void) {
    if (EOPNOTSUPP != 102 || ENOTSUP != 45) return bad("the numbers", EOPNOTSUPP, 102);

    // solisten: a protocol with no connections.
    int ud = socket(AF_UNIX, SOCK_DGRAM, 0), in = socket(AF_INET, SOCK_DGRAM, 0);
    if (expect("listen on a unix datagram socket", listen(ud, 1), EOPNOTSUPP)) return 1;
    if (expect("listen on a UDP socket", listen(in, 1), EOPNOTSUPP)) return 1;

    // accept1: EOPNOTSUPP without connections, EINVAL without a listen.
    if (expect("accept on a datagram socket", accept(ud, NULL, NULL), EOPNOTSUPP)) return 1;
    int us = socket(AF_UNIX, SOCK_STREAM, 0);
    if (expect("accept with no listen", accept(us, NULL, NULL), EINVAL)) return 1;

    // sosend_checks: out-of-band data only on a stream.
    int dp[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, dp) != 0) return bad("socketpair", errno, 0);
    if (expect("MSG_OOB on a datagram socket", send(dp[0], "x", 1, MSG_OOB), EOPNOTSUPP)) return 1;

    // uipc_send and pru_rcvoob: a unix stream has none.
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return bad("socketpair", errno, 0);
    char c;
    if (expect("MSG_OOB on a unix stream", send(sp[0], "x", 1, MSG_OOB), EOPNOTSUPP)) return 1;
    if (expect("receiving MSG_OOB on a unix stream", recv(sp[1], &c, 1, MSG_OOB), EOPNOTSUPP)) return 1;

    // soconnect2: TCP's pru_connect2 is pru_connect2_notsupp.
    int ip[2];
    if (expect("socketpair of TCP", socketpair(AF_INET, SOCK_STREAM, 0, ip), EOPNOTSUPP)) return 1;

    // soconnectlock: a listener connects to nothing.
    char name[64];
    snprintf(name, sizeof name, "/private/var/tmp/sockerr-%d", getpid());
    unlink(name);
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    strlcpy(a.sun_path, name, sizeof a.sun_path);
    a.sun_len = SUN_LEN(&a);
    int ln = socket(AF_UNIX, SOCK_STREAM, 0);
    if (bind(ln, (struct sockaddr *)&a, a.sun_len) != 0 || listen(ln, 1) != 0) return bad("listener", errno, 0);
    if (expect("connect from a listener", connect(ln, (struct sockaddr *)&a, a.sun_len), EOPNOTSUPP)) return 1;
    unlink(name);

    puts("sockerr ok");
    return 0;
}
