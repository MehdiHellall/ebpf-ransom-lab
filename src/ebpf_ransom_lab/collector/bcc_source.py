"""BCC C source for Ubuntu 24.04's Linux 6.8 collector baseline."""


BCC_SOURCE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#ifndef USER_HZ
#define USER_HZ 100
#endif
#define NSEC_PER_SEC 1000000000ULL

#if USER_HZ <= 0 || (NSEC_PER_SEC % USER_HZ) != 0
#error "USER_HZ must divide one second exactly"
#endif

#define FILENAME_CAPACITY 256
#define EVENT_KIND_SYSCALL 1
#define EVENT_KIND_PROCESS_EXIT 2
#define EVENT_FLAG_FILENAME_TRUNCATED 0x80

#define OP_OPEN 1
#define OP_OPENAT 2
#define OP_UNLINK 3
#define OP_UNLINKAT 4
#define OP_PROCESS_EXIT 5

#define LOSS_RINGBUF_RESERVATION 0
#define LOSS_PENDING_MAP_UPDATE 1
#define LOSS_FILENAME_READ 2
#define LOSS_IDENTITY_READ 3

struct event_t {
    __u64 monotonic_ns;
    __u64 process_start_ns;
    __s64 return_value;
    __u32 tgid;
    __u32 tid;
    __u32 open_flags;
    __u16 filename_len;
    __u8 operation;
    __u8 event_kind;
    __u8 filename[FILENAME_CAPACITY];
};

_Static_assert(sizeof(struct event_t) == 296, "event_t ABI size changed");
_Static_assert(__builtin_offsetof(struct event_t, monotonic_ns) == 0,
               "event_t monotonic_ns offset changed");
_Static_assert(__builtin_offsetof(struct event_t, process_start_ns) == 8,
               "event_t process_start_ns offset changed");
_Static_assert(__builtin_offsetof(struct event_t, return_value) == 16,
               "event_t return_value offset changed");
_Static_assert(__builtin_offsetof(struct event_t, tgid) == 24,
               "event_t tgid offset changed");
_Static_assert(__builtin_offsetof(struct event_t, tid) == 28,
               "event_t tid offset changed");
_Static_assert(__builtin_offsetof(struct event_t, open_flags) == 32,
               "event_t open_flags offset changed");
_Static_assert(__builtin_offsetof(struct event_t, filename_len) == 36,
               "event_t filename_len offset changed");
_Static_assert(__builtin_offsetof(struct event_t, operation) == 38,
               "event_t operation offset changed");
_Static_assert(__builtin_offsetof(struct event_t, event_kind) == 39,
               "event_t event_kind offset changed");
_Static_assert(__builtin_offsetof(struct event_t, filename) == 40,
               "event_t filename offset changed");

struct pending_t {
    __u64 process_start_ns;
    __u32 open_flags;
    __u16 filename_len;
    __u8 operation;
    __u8 event_flags;
    __u8 filename[FILENAME_CAPACITY];
};

BPF_HASH(pending, __u64, struct pending_t, 32768);
BPF_ARRAY(loss_counters, __u64, 4);
BPF_RINGBUF_OUTPUT(events, 256);

static __always_inline void count_loss(__u32 index)
{
    __u64 *counter = loss_counters.lookup(&index);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline __u64 process_start_boottime(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *group_leader = 0;
    __u64 start_boottime = 0;
    __u64 tick_ns = NSEC_PER_SEC / USER_HZ;

    int read_result = bpf_probe_read_kernel(&group_leader, sizeof(group_leader),
                                            &task->group_leader);
    if (read_result < 0) {
        count_loss(LOSS_IDENTITY_READ);
        return 0;
    }
    if (!group_leader)
        group_leader = task;
    read_result = bpf_probe_read_kernel(&start_boottime, sizeof(start_boottime),
                                        &group_leader->start_boottime);
    if (read_result < 0)
        count_loss(LOSS_IDENTITY_READ);
    /* /proc/<pid>/stat exposes this field in USER_HZ ticks. Canonicalize
     * before emitting it so workload manifests and collector records agree. */
    return (start_boottime / tick_ns) * tick_ns;
}

static __always_inline int begin_syscall(__u8 operation,
                                          const char *filename,
                                          __u32 open_flags)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_t value = {};
    int copied;

    value.operation = operation;
    value.open_flags = open_flags;
    value.process_start_ns = process_start_boottime();
    if (!value.process_start_ns)
        return 0;
    copied = bpf_probe_read_user_str(value.filename, FILENAME_CAPACITY, filename);
    if (copied > 0) {
        value.filename_len = copied - 1;
        if (copied == FILENAME_CAPACITY)
            value.event_flags |= EVENT_FLAG_FILENAME_TRUNCATED;
    } else
        count_loss(LOSS_FILENAME_READ);

    int update_result = pending.update(&pid_tgid, &value);
    if (update_result < 0)
        count_loss(LOSS_PENDING_MAP_UPDATE);
    return 0;
}

static __always_inline int finish_syscall(__s64 return_value)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_t *value = pending.lookup(&pid_tgid);
    struct event_t *event;

    if (!value)
        return 0;

    event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) {
        count_loss(LOSS_RINGBUF_RESERVATION);
        pending.delete(&pid_tgid);
        return 0;
    }

    event->monotonic_ns = bpf_ktime_get_ns();
    event->process_start_ns = value->process_start_ns;
    event->return_value = return_value;
    event->tgid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->open_flags = value->open_flags;
    event->filename_len = value->filename_len;
    event->operation = value->operation;
    event->event_kind = EVENT_KIND_SYSCALL | value->event_flags;
    bpf_probe_read_kernel(event->filename, sizeof(event->filename), value->filename);

    events.ringbuf_submit(event, 0);
    pending.delete(&pid_tgid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_open)
{
    return begin_syscall(OP_OPEN, (const char *)args->filename, args->flags);
}

TRACEPOINT_PROBE(syscalls, sys_exit_open)
{
    return finish_syscall((__s64)args->ret);
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    return begin_syscall(OP_OPENAT, (const char *)args->filename, args->flags);
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat)
{
    return finish_syscall((__s64)args->ret);
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlink)
{
    return begin_syscall(OP_UNLINK, (const char *)args->pathname, 0);
}

TRACEPOINT_PROBE(syscalls, sys_exit_unlink)
{
    return finish_syscall((__s64)args->ret);
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat)
{
    return begin_syscall(OP_UNLINKAT, (const char *)args->pathname, 0);
}

TRACEPOINT_PROBE(syscalls, sys_exit_unlinkat)
{
    return finish_syscall((__s64)args->ret);
}

TRACEPOINT_PROBE(sched, sched_process_exit)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 process_start_ns;
    struct event_t *event;

    pending.delete(&pid_tgid);
    if (tid != tgid)
        return 0;

    process_start_ns = process_start_boottime();
    if (!process_start_ns)
        return 0;

    event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) {
        count_loss(LOSS_RINGBUF_RESERVATION);
        return 0;
    }

    event->monotonic_ns = bpf_ktime_get_ns();
    event->process_start_ns = process_start_ns;
    event->return_value = 0;
    event->tgid = tgid;
    event->tid = tid;
    event->open_flags = 0;
    event->filename_len = 0;
    event->operation = OP_PROCESS_EXIT;
    event->event_kind = EVENT_KIND_PROCESS_EXIT;
    __builtin_memset(event->filename, 0, sizeof(event->filename));
    events.ringbuf_submit(event, 0);
    return 0;
}
"""
