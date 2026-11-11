// Socket addresses copied out without a length to read: recvfrom with no
// length pointer copies no address (its room is 0), getsockname and
// getpeername copy the length in first (EFAULT without one), and accept
// asked for an address needs one too; asked for none, it needs nothing.

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("sockname: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

int main(void) {
    int fail = 0;
    // A datagram pair: recvfrom with an address buffer and no length.
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)) return bad("socketpair", errno, 0);
    send(sv[0], "x", 1, 0);
    unsigned char from[64];
    memset(from, 0xee, sizeof from);
    char b;
    ssize_t n = recvfrom(sv[1], &b, 1, 0, (struct sockaddr *)from, NULL);
    fail |= n != 1 ? bad("recvfrom", n < 0 ? errno : n, 1) : 0;
    fail |= from[0] != 0xee || from[1] != 0xee ? bad("an address with no length", from[1], 0xee) : 0;

    // getsockname and getpeername: no length is EFAULT.
    struct sockaddr_un un;
    fail |= getsockname(sv[0], (struct sockaddr *)&un, NULL) != -1 || errno != EFAULT ? bad("getsockname, no length", errno, EFAULT) : 0;
    fail |= getpeername(sv[0], (struct sockaddr *)&un, NULL) != -1 || errno != EFAULT ? bad("getpeername, no length", errno, EFAULT) : 0;
    socklen_t len = sizeof un;
    fail |= getsockname(sv[0], (struct sockaddr *)&un, &len) ? bad("getsockname", errno, 0) : 0;
    close(sv[0]);
    close(sv[1]);

    // accept: an address with no length is EFAULT; none asked, none needed.
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in in = {0};
    in.sin_len = sizeof in;
    in.sin_family = AF_INET;
    in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(l, (struct sockaddr *)&in, sizeof in) || listen(l, 4)) return bad("listen", errno, 0);
    socklen_t il = sizeof in;
    getsockname(l, (struct sockaddr *)&in, &il);
    for (int i = 0; i < 2; i++) {
        int c = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(c, (struct sockaddr *)&in, sizeof in)) return bad("connect", errno, 0);
        struct sockaddr_in peer;
        int a = i == 0 ? accept(l, (struct sockaddr *)&peer, NULL) : accept(l, NULL, NULL);
        if (i == 0) {
            fail |= a != -1 || errno != EFAULT ? bad("accept, no length", a < 0 ? errno : 0, EFAULT) : 0;
            // The connection is still there for the next accept.
            if (a >= 0) close(a);
            a = accept(l, NULL, NULL);
        }
        fail |= a < 0 ? bad("accept, no address", errno, 0) : 0;
        close(a);
        close(c);
    }
    close(l);
    if (!fail) printf("sockname ok\n");
    return fail;
}
