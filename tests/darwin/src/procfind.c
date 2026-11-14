// Another process is found by its pid as XNU's proc_find finds it
// (kern_proc.c): from the moment the call that made it returns until its
// exit passes proc_prepareexit (P_REF_DEAD), which comes before its task is
// terminated. csops, task_name_for_pid and proc_pidinfo's live flavors find
// it in that span only; proc_pidinfo's zombie flavors (proc_find_zombref)
// find it from then until it is reaped.
//
// A child spawned POSIX_SPAWN_START_SUSPENDED is found before it runs (its
// p_stat SSTOP): its csops status is the image's, its audit token's identity version is the
// one csops_audittoken takes (another is ESRCH), and its task has a name
// port. A child dying of abort has its EXC_CRASH handler told first
// (proc_prepareexit's task_exception_notify): while the handler holds the
// request the child is still found, and its task named. Once a task's name
// port is dead (its dead-name notification has come), its process is not
// found any more: csops is ESRCH and task_name_for_pid null with
// KERN_FAILURE, whether or not it is a zombie yet. A zombie (waitid
// WNOWAIT) is found only by the zombie flavors, its status SZOMB; a reaped
// pid by none.

#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
int csops_audittoken(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token);
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);

#define CS_OPS_STATUS 0
#define PROC_PIDTASKINFO 4
#define PROC_PIDT_SHORTBSDINFO 13
#define SRUN 2
#define SSTOP 4
#define SZOMB 5

struct shortinfo {
    uint32_t pid, ppid, pgid, status;
    char comm[16];
    uint32_t flags, uid, gid, ruid, rgid, svuid, svgid, rfu;
};

static int bad(const char *what, long got, long want) {
    printf("procfind: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static uint32_t my_status;

// What a live process's pid finds: its csops status (this program's), its
// task's name port (returned in *out), and its p_stat.
static int found(const char *who, pid_t pid, uint32_t stat, mach_port_t *out) {
    char what[96];
    uint32_t st = 0;
    snprintf(what, sizeof what, "%s: csops CS_OPS_STATUS", who);
    if (csops(pid, CS_OPS_STATUS, &st, sizeof st)) return bad(what, errno, 0);
    if (st != my_status) return bad(what, st, my_status);
    mach_port_t n = MACH_PORT_NULL;
    kern_return_t kr = task_name_for_pid(mach_task_self(), pid, &n);
    snprintf(what, sizeof what, "%s: task_name_for_pid", who);
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(n)) return bad(what, kr ? kr : n, 1);
    struct shortinfo si;
    snprintf(what, sizeof what, "%s: PROC_PIDT_SHORTBSDINFO", who);
    if (proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &si, sizeof si) != sizeof si) return bad(what, errno, 0);
    if (si.pid != (uint32_t)pid || si.status != stat) return bad(what, si.status, stat);
    *out = n;
    return 0;
}

// What a pid whose process has exited finds: no csops, no name port, no
// live flavor; the zombie flavor while it is not reaped (`zombie` -1: its
// status either, as its end may not have made it a zombie yet).
static int exited(const char *who, pid_t pid, int zombie) {
    char what[96];
    uint32_t st = 0;
    snprintf(what, sizeof what, "%s: csops", who);
    if (csops(pid, CS_OPS_STATUS, &st, sizeof st) != -1 || errno != ESRCH) return bad(what, errno, ESRCH);
    mach_port_t n = 0x1234;
    kern_return_t kr = task_name_for_pid(mach_task_self(), pid, &n);
    snprintf(what, sizeof what, "%s: task_name_for_pid", who);
    if (kr != KERN_FAILURE || n != MACH_PORT_NULL) return bad(what, kr ? kr : n, KERN_FAILURE);
    char buf[256];
    snprintf(what, sizeof what, "%s: PROC_PIDTASKINFO", who);
    if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, buf, sizeof buf) != 0 || errno != ESRCH) return bad(what, errno, ESRCH);
    struct shortinfo si;
    snprintf(what, sizeof what, "%s: PROC_PIDT_SHORTBSDINFO of the living", who);
    if (proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &si, sizeof si) != 0 || errno != ESRCH) return bad(what, errno, ESRCH);
    snprintf(what, sizeof what, "%s: PROC_PIDT_SHORTBSDINFO of the zombies", who);
    int r = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 1, &si, sizeof si);
    if (zombie == 0) {
        if (r != 0 || errno != ESRCH) return bad(what, errno, ESRCH);
    } else {
        if (r != sizeof si || si.pid != (uint32_t)pid) return bad(what, errno, 0);
        if (zombie > 0 && si.status != SZOMB) return bad(what, si.status, SZOMB);
    }
    return 0;
}

// A port for notifications, and a dead-name request on `name` to it.
static int watch(const char *who, mach_port_t name, mach_port_t *notify) {
    mach_port_t p, prev = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    kern_return_t kr = mach_port_request_notification(mach_task_self(), name, MACH_NOTIFY_DEAD_NAME, 0, p, MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev);
    if (kr) return bad(who, kr, 0);
    *notify = p;
    return 0;
}

// The dead-name notification for `name`.
static int died(const char *who, mach_port_t notify, mach_port_t name) {
    struct {
        mach_dead_name_notification_t n;
        mach_msg_trailer_t trailer;
    } m;
    kern_return_t kr = mach_msg(&m.n.not_header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof m, notify, 60000, MACH_PORT_NULL);
    if (kr || m.n.not_header.msgh_id != MACH_NOTIFY_DEAD_NAME || m.n.not_port != name) return bad(who, kr ? kr : m.n.not_header.msgh_id, MACH_NOTIFY_DEAD_NAME);
    // The notification's own reference to the dead name.
    mach_port_deallocate(mach_task_self(), name);
    return 0;
}

#pragma pack(4)
typedef struct {
    mach_msg_header_t head;
    NDR_record_t ndr;
    int exc;
    mach_msg_type_number_t code_count;
    int64_t code[2];
    int flavor;
    mach_msg_type_number_t state_count;
    natural_t state[ARM_THREAD_STATE64_COUNT];
    mach_msg_trailer_t trailer;
} request_t;

typedef struct {
    mach_msg_header_t head;
    NDR_record_t ndr;
    kern_return_t ret;
    int flavor;
    mach_msg_type_number_t state_count;
    natural_t state[ARM_THREAD_STATE64_COUNT];
} reply_t;
#pragma pack()

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "crash")) abort();
    if (argc > 1) {
        // Waits for its stdin to end.
        char c;
        while (read(0, &c, 1) > 0) {}
        return 0;
    }
    char self[PATH_MAX];
    uint32_t len = sizeof self;
    _NSGetExecutablePath(self, &len);
    char *env[] = {"MallocNanoZone=0", NULL};
    int r, st;
    if (csops(getpid(), CS_OPS_STATUS, &my_status, sizeof my_status)) return bad("its own status", errno, 0);
    // Not entitled to the debug port: asked of as task_for_pid is, which
    // AMFI refuses without Developer Mode.
    mach_port_t d = 0x1234;
    if (debug_control_port_for_pid(mach_task_self(), getpid(), &d) != KERN_FAILURE || d) return bad("debug_control_port_for_pid of itself", d, 0);

    // A child spawned suspended: found before it runs.
    int in[2];
    if (pipe(in)) return bad("pipe", errno, 0);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, in[0], 0);
    posix_spawn_file_actions_addclose(&fa, in[1]);
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_START_SUSPENDED);
    char *args[] = {self, "wait", NULL};
    pid_t pid;
    int e;
    if ((e = posix_spawn(&pid, self, &fa, &at, args, env))) return bad("spawning", e, 0);
    close(in[0]);
    mach_port_t name;
    if ((r = found("the suspended child", pid, SSTOP, &name))) return r;
    audit_token_t tok;
    mach_msg_type_number_t cnt = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t kr = task_info(name, TASK_AUDIT_TOKEN, (task_info_t)&tok, &cnt);
    if (kr || (pid_t)tok.val[5] != pid) return bad("its audit token", kr ? kr : (long)tok.val[5], pid);
    uint32_t cs = 0;
    if (csops_audittoken(pid, CS_OPS_STATUS, &cs, sizeof cs, &tok) || cs != my_status) return bad("csops_audittoken with its token", errno, 0);
    tok.val[7] += 1;
    if (csops_audittoken(pid, CS_OPS_STATUS, &cs, sizeof cs, &tok) != -1 || errno != ESRCH) return bad("csops_audittoken with another identity version", errno, ESRCH);
    d = 0x1234;
    if (debug_control_port_for_pid(mach_task_self(), pid, &d) != KERN_FAILURE || d) return bad("debug_control_port_for_pid of the child", d, 0);

    // It runs and ends: once its task's name port is dead, its pid finds
    // nothing but its zombie.
    mach_port_t notify;
    if ((r = watch("a dead-name request on its name port", name, &notify))) return r;
    kill(pid, SIGCONT);
    close(in[1]);
    if ((r = died("its name port's death", notify, name))) return r;
    if ((r = exited("an ended child", pid, -1))) return r;
    siginfo_t si;
    memset(&si, 0, sizeof si);
    if (waitid(P_PID, pid, &si, WEXITED | WNOWAIT) || si.si_pid != pid) return bad("the zombie", errno, 0);
    if ((r = exited("a zombie", pid, 1))) return r;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st)) return bad("the child's status", st, 0);
    if ((r = exited("a reaped pid", pid, 0))) return r;

    // A child dying of abort, found while its EXC_CRASH handler holds the
    // request, and not once the handler has answered and its task ended.
    mach_port_t p;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
    posix_spawnattr_t ct;
    posix_spawnattr_init(&ct);
    posix_spawnattr_setexceptionports_np(&ct, EXC_MASK_CRASH, p, EXCEPTION_STATE | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    char *cargs[] = {self, "crash", NULL};
    if ((e = posix_spawn(&pid, self, NULL, &ct, cargs, env))) return bad("spawning the crashing child", e, 0);
    request_t req;
    kr = mach_msg(&req.head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof req, p, 60000, MACH_PORT_NULL);
    if (kr || req.head.msgh_id != 2406 || req.exc != EXC_CRASH) return bad("the crash's request", kr ? kr : req.head.msgh_id, 2406);
    if ((r = found("a child its EXC_CRASH handler holds", pid, SRUN, &name))) return r;
    if ((r = watch("a dead-name request on the crashed child's name port", name, &notify))) return r;
    char *after = (char *)req.code + req.code_count * sizeof(int64_t);
    reply_t rep;
    memset(&rep, 0, sizeof rep);
    rep.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req.head.msgh_bits), 0);
    rep.head.msgh_remote_port = req.head.msgh_remote_port;
    rep.head.msgh_id = req.head.msgh_id + 100;
    rep.ndr = NDR_record;
    memcpy(&rep.flavor, after, 4);
    memcpy(&rep.state_count, after + 4, 4);
    memcpy(rep.state, after + 8, rep.state_count * sizeof(natural_t));
    rep.head.msgh_size = sizeof rep;
    if ((kr = mach_msg(&rep.head, MACH_SEND_MSG, rep.head.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL))) return bad("answering the crash", kr, 0);
    if ((r = died("the crashed child's name port's death", notify, name))) return r;
    if ((r = exited("a crashed child", pid, -1))) return r;
    if (waitpid(pid, &st, 0) != pid || !WIFSIGNALED(st) || WTERMSIG(st) != SIGABRT) return bad("the crashed child's death", st, SIGABRT);
    if ((r = exited("a crashed child, reaped", pid, 0))) return r;
    printf("procfind ok\n");
    return 0;
}
