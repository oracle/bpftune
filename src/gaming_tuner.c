/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Gaming Performance Tuner - userspace controller
 * Applies network tuning profiles when the eBPF detector reports activity.
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <bpftune/libbpftune.h>
#include <bpftune/bpftune.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include "gaming_tuner.h"
#include "gaming_tuner.skel.h"
#include "gaming_tuner.skel.legacy.h"
#include "gaming_tuner.skel.nobtf.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

static struct bpftunable_desc tunable_descs[] = {
    { GAMING_TUNABLE_RMEM_DEFAULT, BPFTUNABLE_SYSCTL,
      "net.core.rmem_default", 0, 1 },
    { GAMING_TUNABLE_RMEM_MAX, BPFTUNABLE_SYSCTL,
      "net.core.rmem_max", 0, 1 },
    { GAMING_TUNABLE_WMEM_DEFAULT, BPFTUNABLE_SYSCTL,
      "net.core.wmem_default", 0, 1 },
    { GAMING_TUNABLE_WMEM_MAX, BPFTUNABLE_SYSCTL,
      "net.core.wmem_max", 0, 1 },
    { GAMING_TUNABLE_NETDEV_MAX_BACKLOG, BPFTUNABLE_SYSCTL,
      "net.core.netdev_max_backlog", 0, 1 },
    { GAMING_TUNABLE_NETDEV_BUDGET, BPFTUNABLE_SYSCTL,
      "net.core.netdev_budget", 0, 1 },
    { GAMING_TUNABLE_NETDEV_BUDGET_USECS, BPFTUNABLE_SYSCTL,
      "net.core.netdev_budget_usecs", 0, 1 },
    { GAMING_TUNABLE_UDP_MEM, BPFTUNABLE_SYSCTL,
      "net.ipv4.udp_mem", BPFTUNABLE_STRING, 1 },
    { GAMING_TUNABLE_BUSY_READ, BPFTUNABLE_SYSCTL,
      "net.core.busy_read", 0, 1 },
    { GAMING_TUNABLE_BUSY_POLL, BPFTUNABLE_SYSCTL,
      "net.core.busy_poll", 0, 1 },
    { GAMING_TUNABLE_UDP_EARLY_DEMUX, BPFTUNABLE_SYSCTL,
      "net.ipv4.udp_early_demux", 0, 1 },
};

static struct bpftunable_scenario scenarios[] = {
    BPFTUNABLE_SCENARIO_FLAGS(GAMING_SCENARIO_DETECTED, "gaming_detected",
                              "Gaming traffic pattern detected",
                              BPFTUNABLE_SCENARIO_QUIET),
    BPFTUNABLE_SCENARIO_FLAGS(GAMING_SCENARIO_ENDED, "gaming_ended",
                              "Gaming session has ended",
                              BPFTUNABLE_SCENARIO_QUIET),
};

struct profile_entry {
    unsigned int index;
    long value;
    const char *str_value;
};

struct profile_definition {
    const char *name;
    const struct profile_entry *entries;
    size_t entry_count;
};

static const struct profile_entry casual_entries[] = {
    { GAMING_TUNABLE_RMEM_DEFAULT, 262144, NULL },
    { GAMING_TUNABLE_RMEM_MAX, 8388608, NULL },
    { GAMING_TUNABLE_WMEM_DEFAULT, 262144, NULL },
    { GAMING_TUNABLE_WMEM_MAX, 8388608, NULL },
    { GAMING_TUNABLE_NETDEV_MAX_BACKLOG, 5000, NULL },
    { GAMING_TUNABLE_NETDEV_BUDGET, 400, NULL },
    { GAMING_TUNABLE_NETDEV_BUDGET_USECS, 8000, NULL },
    { GAMING_TUNABLE_UDP_MEM, 0, "65536 436900 8388608" },
    { GAMING_TUNABLE_BUSY_READ, 25, NULL },
    { GAMING_TUNABLE_BUSY_POLL, 25, NULL },
    { GAMING_TUNABLE_UDP_EARLY_DEMUX, 1, NULL },
};

static const struct profile_entry competitive_entries[] = {
    { GAMING_TUNABLE_RMEM_DEFAULT, 262144, NULL },
    { GAMING_TUNABLE_RMEM_MAX, 16777216, NULL },
    { GAMING_TUNABLE_WMEM_DEFAULT, 262144, NULL },
    { GAMING_TUNABLE_WMEM_MAX, 16777216, NULL },
    { GAMING_TUNABLE_NETDEV_MAX_BACKLOG, 5000, NULL },
    { GAMING_TUNABLE_NETDEV_BUDGET, 600, NULL },
    { GAMING_TUNABLE_NETDEV_BUDGET_USECS, 8000, NULL },
    { GAMING_TUNABLE_UDP_MEM, 0, "102400 873800 16777216" },
    { GAMING_TUNABLE_BUSY_READ, 50, NULL },
    { GAMING_TUNABLE_BUSY_POLL, 50, NULL },
    { GAMING_TUNABLE_UDP_EARLY_DEMUX, 1, NULL },
};

static const struct profile_entry intense_entries[] = {
    { GAMING_TUNABLE_RMEM_DEFAULT, 262144, NULL },
    { GAMING_TUNABLE_RMEM_MAX, 33554432, NULL },
    { GAMING_TUNABLE_WMEM_DEFAULT, 262144, NULL },
    { GAMING_TUNABLE_WMEM_MAX, 33554432, NULL },
    { GAMING_TUNABLE_NETDEV_MAX_BACKLOG, 5000, NULL },
    { GAMING_TUNABLE_NETDEV_BUDGET, 800, NULL },
    { GAMING_TUNABLE_NETDEV_BUDGET_USECS, 8000, NULL },
    { GAMING_TUNABLE_UDP_MEM, 0, "204800 1747600 33554432" },
    { GAMING_TUNABLE_BUSY_READ, 75, NULL },
    { GAMING_TUNABLE_BUSY_POLL, 75, NULL },
    { GAMING_TUNABLE_UDP_EARLY_DEMUX, 1, NULL },
};

static const struct profile_definition profiles[] = {
    { "CASUAL", casual_entries, ARRAY_SIZE(casual_entries) },
    { "COMPETITIVE", competitive_entries, ARRAY_SIZE(competitive_entries) },
    { "INTENSE", intense_entries, ARRAY_SIZE(intense_entries) },
};

#define SUMMARY_BUFFER_SIZE 512

struct summary_buffer {
    char data[SUMMARY_BUFFER_SIZE];
    size_t len;
    int truncated;
};

static void summary_buffer_init(struct summary_buffer *buffer)
{
    if (!buffer)
        return;

    buffer->data[0] = '\0';
    buffer->len = 0;
    buffer->truncated = 0;
}

static void summary_buffer_append(struct summary_buffer *buffer, const char *name,
                                  const char *value)
{
    size_t remaining;
    int written;

    if (!buffer || !name)
        return;

    if (!value)
        value = "";

    if (buffer->truncated)
        return;

    remaining = sizeof(buffer->data) - buffer->len;
    if (remaining == 0) {
        buffer->truncated = 1;
        return;
    }

    written = snprintf(buffer->data + buffer->len, remaining, "%s%s=%s",
                       buffer->len ? ", " : "", name, value);

    if (written < 0) {
        buffer->truncated = 1;
        buffer->data[sizeof(buffer->data) - 1] = '\0';
        return;
    }

    if ((size_t)written >= remaining) {
        buffer->len = sizeof(buffer->data) - 1;
        buffer->data[buffer->len] = '\0';
        buffer->truncated = 1;
        return;
    }

    buffer->len += (size_t)written;
}

static int summary_buffer_is_empty(const struct summary_buffer *buffer)
{
    return !buffer || buffer->len == 0;
}

static const char *summary_buffer_text(const struct summary_buffer *buffer)
{
    return (buffer && buffer->len) ? buffer->data : "";
}

static int summary_buffer_truncated(const struct summary_buffer *buffer)
{
    return buffer && buffer->truncated;
}

static char gaming_tolower_char(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    return c;
}

static int gaming_comm_matches(const char *comm, const char *pattern)
{
    size_t i;

    if (!comm || !pattern)
        return 0;

    for (i = 0; i < GAMING_TUNER_COMM_LEN; i++) {
        char p = pattern[i];

        if (p == '*')
            return 1;

        char c = comm[i];

        if (p == '\0')
            return c == '\0';
        if (c == '\0')
            return 0;
        if (gaming_tolower_char(c) != p)
            return 0;
    }

    return pattern[GAMING_TUNER_COMM_LEN - 1] == '*';
}

static void gaming_copy_comm(char *dst, size_t dst_len, const char *src)
{
    size_t copy_len;

    if (!dst || !dst_len)
        return;

    memset(dst, 0, dst_len);

    if (!src)
        return;

    copy_len = strnlen(src, dst_len - 1);
    if (copy_len)
        memcpy(dst, src, copy_len);
}

static void gaming_lineage_append(char *buffer, size_t buffer_len, const char *entry)
{
    size_t used;
    int written;

    if (!buffer || !buffer_len || !entry || !entry[0])
        return;

    used = strnlen(buffer, buffer_len);
    if (used >= buffer_len - 1)
        return;

    written = snprintf(buffer + used, buffer_len - used, "%s%s",
                       used ? " <- " : "", entry);
    if (written < 0)
        return;

    if ((size_t)written >= buffer_len - used)
        buffer[buffer_len - 1] = '\0';
}

static int gaming_launcher_comm(const char *comm)
{
    if (!comm || !comm[0])
        return 0;

#define GAMING_LAUNCHER_ENTRY(str) \
    if (gaming_comm_matches(comm, str)) \
        return 1;

    GAMING_TUNER_FOR_EACH_LAUNCHER(GAMING_LAUNCHER_ENTRY)

#undef GAMING_LAUNCHER_ENTRY

    return 0;
}

static int gaming_read_proc_status(pid_t pid, char *comm, size_t comm_len, pid_t *ppid)
{
    char path[64];
    FILE *f;
    char line[256];
    int need_comm = comm && comm_len;
    int need_ppid = ppid != NULL;

    if (comm && comm_len)
        comm[0] = '\0';
    if (ppid)
        *ppid = -1;

    if (pid <= 0)
        return -EINVAL;

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    f = fopen(path, "re");
    if (!f)
        return -errno;

    while ((need_comm || need_ppid) && fgets(line, sizeof(line), f)) {
        if (need_comm && strncmp(line, "Name:", 5) == 0) {
            char *value = line + 5;

            while (*value && isspace((unsigned char)*value))
                value++;

            char *end = value + strlen(value);
            while (end > value && isspace((unsigned char)end[-1]))
                end--;

            size_t len = (size_t)(end - value);
            if (len >= comm_len)
                len = comm_len ? comm_len - 1 : 0;

            if (comm && comm_len) {
                if (len && comm_len)
                    memcpy(comm, value, len);
                if (comm_len)
                    comm[len] = '\0';
            }

            need_comm = 0;
        } else if (need_ppid && strncmp(line, "PPid:", 5) == 0) {
            char *value = line + 5;

            while (*value && isspace((unsigned char)*value))
                value++;

            long parsed = strtol(value, NULL, 10);
            if (ppid)
                *ppid = (pid_t)parsed;
            need_ppid = 0;
        }
    }

    fclose(f);

    if ((comm && comm_len && comm[0] == '\0') && need_comm)
        return -ENOENT;
    if (ppid && *ppid < 0 && need_ppid)
        return -ENOENT;

    return 0;
}

static int gaming_cmdline_launcher(pid_t pid)
{
    char path[64];
    int fd;
    ssize_t len;
    static const size_t buf_sz = 4096;
    char *buf;
    int trusted = 0;

    if (pid <= 0)
        return 0;

    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return 0;

    buf = malloc(buf_sz);
    if (!buf) {
        close(fd);
        return 0;
    }

    len = read(fd, buf, buf_sz - 1);
    close(fd);

    if (len <= 0) {
        free(buf);
        return 0;
    }

    for (ssize_t i = 0; i < len; i++) {
        if (buf[i] == '\0')
            buf[i] = ' ';
    }
    buf[len] = '\0';

#define GAMING_LAUNCHER_CMD_ENTRY(str) \
    if (!trusted && strcasestr(buf, (str))) \
        trusted = 1;

    GAMING_TUNER_FOR_EACH_LAUNCHER_CMD(GAMING_LAUNCHER_CMD_ENTRY)

#undef GAMING_LAUNCHER_CMD_ENTRY

    free(buf);
    return trusted;
}

static int gaming_process_trusted(pid_t pid, char *lineage, size_t lineage_len,
                                  int *matched_cmdline)
{
    pid_t current = pid;

    if (lineage && lineage_len)
        lineage[0] = '\0';
    if (matched_cmdline)
        *matched_cmdline = 0;

    for (int depth = 0; depth < 6; depth++) {
        char comm[GAMING_TUNER_COMM_LEN] = { 0 };
        pid_t parent = -1;
        int ret;

        if (current <= 0)
            break;

        ret = gaming_read_proc_status(current, comm, sizeof(comm), &parent);
        if (ret < 0) {
            if (depth == 0)
                return 0;
            break;
        }

        gaming_lineage_append(lineage, lineage_len, comm);

        if (gaming_launcher_comm(comm) || gaming_cmdline_launcher(current))
            {
                if (matched_cmdline && !gaming_launcher_comm(comm))
                    *matched_cmdline = 1;
                return 1;
            }

        if (parent <= 0 || parent == current)
            break;

        current = parent;
    }

    return 0;
}

static size_t clamp_profile_index(int intensity)
{
    if (intensity < 0)
        return 0;

    size_t idx = (size_t)intensity;

    if (idx >= ARRAY_SIZE(profiles))
        return ARRAY_SIZE(profiles) - 1;

    return idx;
}

struct gaming_state {
    int active;
    int intensity;
    int current_pps;
    time_t start_time;
    unsigned int optimization_count;
    unsigned int revert_count;
    unsigned int active_ifindex;
    char active_ifname[IF_NAMESIZE];
    char active_comm[GAMING_TUNER_COMM_LEN];
    int pending_revert;
    time_t revert_deadline;
};

static struct gaming_state g_state;
static pthread_mutex_t g_state_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_state_cond = PTHREAD_COND_INITIALIZER;
static pthread_t g_revert_thread;
static int g_revert_thread_started;
static int g_revert_thread_stop;
static struct bpftuner *g_tuner;

#define GAMING_REVERT_GRACE_SECONDS 10
#define GAMING_MAX_INTERFACES 8

struct interface_tuning_state {
    unsigned int ifindex;
    char ifname[IF_NAMESIZE];
    struct ethtool_coalesce baseline;
    __u32 current_rx_usecs;
    __u32 current_tx_usecs;
    int baseline_valid;
    int applied;
};

static struct interface_tuning_state g_interfaces[GAMING_MAX_INTERFACES];

static int gaming_ethtool_get(const char *ifname, struct ethtool_coalesce *coal);
static int gaming_ethtool_set(const char *ifname, const struct ethtool_coalesce *coal);
static struct interface_tuning_state *gaming_interface_state(unsigned int ifindex);
static int gaming_interface_prepare(struct interface_tuning_state *state);
static int gaming_interface_restore_locked(struct interface_tuning_state *state);
static void apply_interface_tuning(unsigned int ifindex, int intensity);
static int restore_all_interfaces(void);
static void gaming_schedule_revert(void);
static void gaming_start_revert_worker(void);
static void gaming_stop_revert_worker(void);
static void *gaming_revert_worker(void *arg);
static void revert_optimizations(struct bpftuner *tuner, int force);

static int gaming_ethtool_get(const char *ifname, struct ethtool_coalesce *coal)
{
    struct ifreq ifr;
    struct ethtool_coalesce request = { .cmd = ETHTOOL_GCOALESCE };
    int fd;

    if (!ifname || !coal)
        return -EINVAL;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -errno;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    ifr.ifr_data = (void *)&request;

    if (ioctl(fd, SIOCETHTOOL, &ifr) < 0) {
        int err = -errno;
        close(fd);
        return err;
    }

    close(fd);
    *coal = request;
    return 0;
}

static int gaming_ethtool_set(const char *ifname, const struct ethtool_coalesce *coal)
{
    struct ifreq ifr;
    struct ethtool_coalesce request;
    int fd;

    if (!ifname || !coal)
        return -EINVAL;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -errno;

    memset(&ifr, 0, sizeof(ifr));
    request = *coal;
    request.cmd = ETHTOOL_SCOALESCE;

    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    ifr.ifr_data = (void *)&request;

    if (ioctl(fd, SIOCETHTOOL, &ifr) < 0) {
        int err = -errno;
        close(fd);
        return err;
    }

    close(fd);
    return 0;
}

static struct interface_tuning_state *gaming_interface_state(unsigned int ifindex)
{
    struct interface_tuning_state *free_state = NULL;

    if (!ifindex)
        return NULL;

    for (size_t i = 0; i < GAMING_MAX_INTERFACES; i++) {
        struct interface_tuning_state *state = &g_interfaces[i];

        if (state->ifindex == ifindex)
            return state;
        if (!state->ifindex && !free_state)
            free_state = state;
    }

    if (!free_state)
        return NULL;

    memset(free_state, 0, sizeof(*free_state));
    free_state->ifindex = ifindex;
    return free_state;
}

static int gaming_interface_prepare(struct interface_tuning_state *state)
{
    int ret;

    if (!state)
        return -EINVAL;

    if (!if_indextoname(state->ifindex, state->ifname)) {
        ret = -errno;
        bpftune_log(LOG_DEBUG,
                    "gaming: unable to resolve ifindex %u: %s",
                    state->ifindex, strerror(-ret));
        return ret;
    }

    if (state->baseline_valid)
        return 0;

    ret = gaming_ethtool_get(state->ifname, &state->baseline);
    if (ret) {
        bpftune_log(LOG_DEBUG,
                    "gaming: failed to read ethtool coalesce for %s: %s",
                    state->ifname, strerror(-ret));
        return ret;
    }

    state->current_rx_usecs = state->baseline.rx_coalesce_usecs;
    state->current_tx_usecs = state->baseline.tx_coalesce_usecs;
    state->baseline_valid = 1;
    state->applied = 0;

    return 0;
}

static int gaming_interface_restore_locked(struct interface_tuning_state *state)
{
    int ret;

    if (!state || !state->ifindex || !state->baseline_valid)
        return 0;

    if (!state->applied &&
        state->current_rx_usecs == state->baseline.rx_coalesce_usecs &&
        state->current_tx_usecs == state->baseline.tx_coalesce_usecs)
        return 0;

    ret = gaming_ethtool_set(state->ifname, &state->baseline);
    if (ret) {
        bpftune_log(LOG_DEBUG,
                    "gaming: failed to restore coalesce on %s: %s",
                    state->ifname, strerror(-ret));
        return ret;
    }

    state->current_rx_usecs = state->baseline.rx_coalesce_usecs;
    state->current_tx_usecs = state->baseline.tx_coalesce_usecs;
    state->applied = 0;

    bpftune_log(LOG_INFO,
                "Restored interrupt coalescing on %s to baseline %u usecs",
                state->ifname, state->baseline.rx_coalesce_usecs);

    return 0;
}

static void apply_interface_tuning(unsigned int ifindex, int intensity)
{
    struct interface_tuning_state *state;
    unsigned int target_usecs;
    int ret;

    if (!ifindex)
        return;

    pthread_mutex_lock(&g_state_lock);

    state = gaming_interface_state(ifindex);
    if (!state) {
        pthread_mutex_unlock(&g_state_lock);
        bpftune_log(LOG_DEBUG,
                    "gaming: no available slot for interface index %u", ifindex);
        return;
    }

    ret = gaming_interface_prepare(state);
    if (ret) {
        pthread_mutex_unlock(&g_state_lock);
        return;
    }

    if (intensity <= 0) {
        gaming_interface_restore_locked(state);
        pthread_mutex_unlock(&g_state_lock);
        return;
    }

    target_usecs = (intensity >= 2) ? 0 : 10;

    if (state->current_rx_usecs == target_usecs &&
        state->current_tx_usecs == target_usecs) {
        pthread_mutex_unlock(&g_state_lock);
        return;
    }

    struct ethtool_coalesce desired = state->baseline;

    desired.rx_coalesce_usecs = target_usecs;
    desired.tx_coalesce_usecs = target_usecs;
    desired.use_adaptive_rx_coalesce = 0;
    desired.use_adaptive_tx_coalesce = 0;

    ret = gaming_ethtool_set(state->ifname, &desired);
    if (ret) {
        bpftune_log(LOG_DEBUG,
                    "gaming: failed to set coalesce on %s: %s",
                    state->ifname, strerror(-ret));
        pthread_mutex_unlock(&g_state_lock);
        return;
    }

    state->current_rx_usecs = target_usecs;
    state->current_tx_usecs = target_usecs;
    state->applied = (target_usecs != state->baseline.rx_coalesce_usecs ||
                      target_usecs != state->baseline.tx_coalesce_usecs);

    bpftune_log(LOG_INFO,
                "Adjusted %s interrupt coalescing to %u usecs for gaming intensity %d",
                state->ifname, target_usecs, intensity);

    pthread_mutex_unlock(&g_state_lock);
}

static int restore_all_interfaces(void)
{
    int failures = 0;

    pthread_mutex_lock(&g_state_lock);
    for (size_t i = 0; i < GAMING_MAX_INTERFACES; i++) {
        struct interface_tuning_state *state = &g_interfaces[i];

        if (!state->ifindex || !state->baseline_valid)
            continue;

        if (gaming_interface_restore_locked(state) < 0)
            failures++;
    }
    pthread_mutex_unlock(&g_state_lock);

    return failures;
}

static void gaming_schedule_revert(void)
{
    time_t now = time(NULL);

    pthread_mutex_lock(&g_state_lock);
    if (!g_state.active) {
        g_state.pending_revert = 0;
        g_state.revert_deadline = 0;
        pthread_mutex_unlock(&g_state_lock);
        return;
    }

    g_state.pending_revert = 1;
    g_state.revert_deadline = now + GAMING_REVERT_GRACE_SECONDS;
    pthread_cond_broadcast(&g_state_cond);
    pthread_mutex_unlock(&g_state_lock);

    bpftune_log(LOG_DEBUG,
                "Gaming traffic paused; baseline restore scheduled in %d seconds",
                GAMING_REVERT_GRACE_SECONDS);
}

static void gaming_start_revert_worker(void)
{
    if (g_revert_thread_started)
        return;

    g_revert_thread_stop = 0;
    int ret = pthread_create(&g_revert_thread, NULL, gaming_revert_worker, NULL);
    if (ret == 0) {
        g_revert_thread_started = 1;
    } else {
        bpftune_log(LOG_WARNING, "gaming: failed to start revert worker: %s",
                    strerror(ret));
    }
}

static void gaming_stop_revert_worker(void)
{
    if (!g_revert_thread_started)
        return;

    pthread_mutex_lock(&g_state_lock);
    g_revert_thread_stop = 1;
    pthread_cond_broadcast(&g_state_cond);
    pthread_mutex_unlock(&g_state_lock);

    pthread_join(g_revert_thread, NULL);
    g_revert_thread_started = 0;
    g_revert_thread_stop = 0;
}

static void *gaming_revert_worker(void *arg)
{
    (void)arg;

    while (1) {
        pthread_mutex_lock(&g_state_lock);
        while (!g_state.pending_revert && !g_revert_thread_stop)
            pthread_cond_wait(&g_state_cond, &g_state_lock);

        if (g_revert_thread_stop) {
            pthread_mutex_unlock(&g_state_lock);
            break;
        }

        while (g_state.pending_revert && !g_revert_thread_stop) {
            time_t now = time(NULL);

            if (now >= g_state.revert_deadline) {
                struct bpftuner *tuner = g_tuner;

                g_state.pending_revert = 0;
                pthread_mutex_unlock(&g_state_lock);
                if (tuner)
                    revert_optimizations(tuner, 0);
                pthread_mutex_lock(&g_state_lock);
                break;
            }

            time_t wait_seconds = g_state.revert_deadline - now;
            struct timespec ts;

            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += wait_seconds;

            if (pthread_cond_timedwait(&g_state_cond, &g_state_lock, &ts) == ETIMEDOUT)
                continue;
        }

        pthread_mutex_unlock(&g_state_lock);
    }

    return NULL;
}

static void apply_profile(struct bpftuner *tuner, int profile_idx, int conservative)
{
    size_t requested = clamp_profile_index(profile_idx);
    size_t effective = conservative && requested > 0 ? requested - 1 : requested;
    const struct profile_definition *profile = &profiles[effective];
    const char *profile_name = profile->name;
    struct summary_buffer summary;
    int applied = 0;

    summary_buffer_init(&summary);

    if (profile_idx != (int)requested) {
        bpftune_log(LOG_DEBUG, "Clamped gaming profile index %d to %zu", profile_idx,
                    requested);
    }

    bpftune_log(LOG_DEBUG, "Applying %s gaming profile%s", profile_name,
                conservative ? " (conservative mode)" : "");

    for (size_t i = 0; i < profile->entry_count; i++) {
        const struct profile_entry *entry = &profile->entries[i];
        const char *str_val = entry->str_value;
        long val = entry->value;
        unsigned int index = entry->index;
        struct bpftunable *tunable = bpftuner_tunable(tuner, index);
        int ret = 0;

        if (!tunable)
            continue;

        if ((tunable->desc.flags & BPFTUNABLE_STRING) && str_val) {
            ret = bpftuner_tunable_sysctl_write(tuner, index, GAMING_SCENARIO_DETECTED,
                                                bpftune_global_netns_cookie(), 1,
                                                (void *)str_val, NULL);
        } else {
            ret = bpftuner_tunable_sysctl_write(tuner, index, GAMING_SCENARIO_DETECTED,
                                                bpftune_global_netns_cookie(), 1,
                                                &val, NULL);
        }

        if (ret < 0) {
            bpftune_log(LOG_WARNING,
                        "Failed to set '%s' for %s gaming profile: %s",
                        tunable->desc.name, profile_name, strerror(-ret));
            continue;
        }

        char value_buf[128];
        const char *value_str = str_val;

        if (!value_str) {
            snprintf(value_buf, sizeof(value_buf), "%ld", val);
            value_str = value_buf;
        }

        summary_buffer_append(&summary, tunable->desc.name, value_str);

        applied = 1;
    }

    pthread_mutex_lock(&g_state_lock);
    if (applied) {
        g_state.active = 1;
        g_state.start_time = time(NULL);
        g_state.optimization_count++;
    }
    g_state.pending_revert = 0;
    g_state.revert_deadline = 0;
    pthread_cond_broadcast(&g_state_cond);
    pthread_mutex_unlock(&g_state_lock);

    if (applied) {
        const char *details = summary_buffer_is_empty(&summary) ?
                              "(no tunables changed)" :
                              summary_buffer_text(&summary);
        bpftune_log(LOG_NOTICE, "Applied %s profile: %s%s",
                    profile_name,
                    details,
                    summary_buffer_truncated(&summary) ? " ..." : "");

        pthread_mutex_lock(&g_state_lock);
        g_state.intensity = (int)requested;
        pthread_mutex_unlock(&g_state_lock);
    }
}

static void revert_optimizations(struct bpftuner *tuner, int force)
{
    int active;
    int dirty;
    struct summary_buffer summary;
    int restored = 0;

    summary_buffer_init(&summary);

    pthread_mutex_lock(&g_state_lock);
    active = g_state.active;
    dirty = g_state.optimization_count > g_state.revert_count;

    if (!force && !active) {
        g_state.pending_revert = 0;
        g_state.revert_deadline = 0;
        pthread_mutex_unlock(&g_state_lock);
        return;
    }

    if (force && !active && !dirty) {
        g_state.pending_revert = 0;
        g_state.revert_deadline = 0;
        pthread_mutex_unlock(&g_state_lock);
        return;
    }

    g_state.pending_revert = 0;
    g_state.revert_deadline = 0;
    pthread_mutex_unlock(&g_state_lock);

    bpftune_log(LOG_NOTICE, "Reverting gaming optimizations");

    int tunable_failures = 0;
    int interface_failures = 0;
    struct bpftunable *t;

    bpftuner_for_each_tunable(tuner, t) {
        int ret;

        if (t->desc.flags & BPFTUNABLE_STRING) {
            ret = bpftuner_tunable_sysctl_write(tuner, t->desc.id, GAMING_SCENARIO_ENDED,
                                                bpftune_global_netns_cookie(), 1,
                                                (void *)t->initial_str, NULL);
        } else {
            long val = t->initial_values[0];

            ret = bpftuner_tunable_sysctl_write(tuner, t->desc.id, GAMING_SCENARIO_ENDED,
                                                bpftune_global_netns_cookie(), 1,
                                                &val, NULL);
        }

        if (ret < 0) {
            bpftune_log(LOG_WARNING, "Failed to restore '%s' to baseline: %s",
                        t->desc.name, strerror(-ret));
            tunable_failures++;
            continue;
        }

        char value_buf[128];
        const char *value_str;

        if (t->desc.flags & BPFTUNABLE_STRING) {
            value_str = t->initial_str[0] ? t->initial_str : "";
        } else {
            size_t buf_len = 0;

            value_buf[0] = '\0';
            for (__u8 i = 0; i < t->desc.num_values; i++) {
                int written = snprintf(value_buf + buf_len,
                                       sizeof(value_buf) - buf_len,
                                       "%s%ld",
                                       buf_len ? " " : "",
                                       t->initial_values[i]);
                if (written < 0)
                    written = 0;
                if ((size_t)written >= sizeof(value_buf) - buf_len) {
                    buf_len = sizeof(value_buf) - 1;
                    value_buf[buf_len] = '\0';
                    break;
                }
                buf_len += (size_t)written;
            }

            value_str = value_buf;
        }

        summary_buffer_append(&summary, t->desc.name, value_str);
        restored++;
    }

    interface_failures = restore_all_interfaces();

    pthread_mutex_lock(&g_state_lock);
    if (tunable_failures == 0 && interface_failures == 0) {
        g_state.active = 0;
        g_state.revert_count++;
        g_state.intensity = 0;
        g_state.active_ifindex = 0;
        g_state.active_ifname[0] = '\0';
        g_state.active_comm[0] = '\0';
        pthread_cond_broadcast(&g_state_cond);
        pthread_mutex_unlock(&g_state_lock);
        if (restored) {
            const char *details = summary_buffer_is_empty(&summary) ?
                                  "baseline already active" :
                                  summary_buffer_text(&summary);
            bpftune_log(LOG_NOTICE, "Reverted gaming tunables: %s%s",
                        details,
                        summary_buffer_truncated(&summary) ? " ..." : "");
        } else {
            bpftune_log(LOG_DEBUG, "Gaming profile settings already at baseline");
        }
        return;
    }

    g_state.pending_revert = 1;
    g_state.revert_deadline = time(NULL) + GAMING_REVERT_GRACE_SECONDS;
    pthread_cond_broadcast(&g_state_cond);
    pthread_mutex_unlock(&g_state_lock);

    if (interface_failures) {
        bpftune_log(LOG_WARNING,
                    "Failed to restore interrupt coalescing on %d interface(s); will retry",
                    interface_failures);
    }

    if (tunable_failures) {
        bpftune_log(LOG_WARNING,
                    "Failed to restore %d gaming tunable(s); will retry in %d seconds",
                    tunable_failures,
                    GAMING_REVERT_GRACE_SECONDS);
    } else {
        bpftune_log(LOG_WARNING,
                    "Gaming tunables restored but interface rollback still pending; retrying in %d seconds",
                    GAMING_REVERT_GRACE_SECONDS);
    }
}


int init(struct bpftuner *tuner)
{
    int ret = bpftuner_tunables_init(tuner, ARRAY_SIZE(tunable_descs), tunable_descs,
                                     ARRAY_SIZE(scenarios), scenarios);
    if (ret != 0) {
        bpftune_log(LOG_ERR, "Failed to initialize gaming tuner descriptors: %d", ret);
        return ret;
    }

    if (bpftune_bpf_support() == BPFTUNE_SUPPORT_NONE) {
        bpftune_log(LOG_ERR, "Gaming tuner requires BPF support");
        return -1;
    }

    pthread_mutex_lock(&g_state_lock);
    g_state = (struct gaming_state){0};
    pthread_mutex_unlock(&g_state_lock);
    memset(g_interfaces, 0, sizeof(g_interfaces));

    g_tuner = tuner;
    gaming_start_revert_worker();

    bpftune_log(LOG_NOTICE,
                "Gaming tuner ready: tracking UDP payloads ≤%u bytes with ≥%u pkt/s sustained for detection",
                GAMING_TUNER_UDP_MAX_SIZE, GAMING_TUNER_UDP_MIN_PPS);

    return bpftuner_bpf_init(gaming, tuner, NULL);
}

void fini(struct bpftuner *tuner)
{
    gaming_stop_revert_worker();

    pthread_mutex_lock(&g_state_lock);
    int active = g_state.active;
    int dirty = g_state.optimization_count > g_state.revert_count;
    pthread_mutex_unlock(&g_state_lock);

    if (active || dirty)
        revert_optimizations(tuner, 1);

    bpftuner_bpf_fini(tuner);
    g_tuner = NULL;
}

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
                   __attribute__((unused)) void *ctx)
{
    if (!event)
        return;

    switch (event->scenario_id) {
    case GAMING_SCENARIO_DETECTED: {
        struct gaming_event_data data = {};
        char ifname[IF_NAMESIZE] = { 0 };
        char comm[GAMING_TUNER_COMM_LEN] = { 0 };
        int intensity;
        int pps;
        long variance;
        unsigned int ifindex;
        size_t profile_idx;
        const char *profile_name;

        memcpy(&data, event->raw_data, sizeof(data));

        intensity = (int)data.intensity;
        pps = (int)data.pps;
        variance = (long)data.variance;
        ifindex = data.ifindex;
        profile_idx = clamp_profile_index(intensity);
        profile_name = profiles[profile_idx].name;

        gaming_copy_comm(comm, sizeof(comm), data.comm);

        if (ifindex)
            if_indextoname(ifindex, ifname);

        if (!gaming_launcher_comm(comm)) {
            pid_t pid = (pid_t)event->pid;
            char lineage[256] = { 0 };
            int matched_cmdline = 0;

            if (!gaming_process_trusted(pid, lineage, sizeof(lineage),
                                        &matched_cmdline)) {
                bpftune_log(LOG_DEBUG,
                            "Ignoring gaming detection from untrusted lineage (pid: %d, process: %s%s%s)",
                            event->pid,
                            comm[0] ? comm : "",
                            lineage[0] ? ", lineage: " : "",
                            lineage[0] ? lineage : "");
                break;
            }
        }

        pthread_mutex_lock(&g_state_lock);
        g_state.intensity = intensity;
        g_state.current_pps = pps;
        g_state.pending_revert = 0;
        g_state.revert_deadline = 0;
        g_state.active_ifindex = ifindex;
        if (ifindex && ifname[0])
            snprintf(g_state.active_ifname, sizeof(g_state.active_ifname), "%s", ifname);
        else
            g_state.active_ifname[0] = '\0';
        g_state.active_ifname[sizeof(g_state.active_ifname) - 1] = '\0';
        gaming_copy_comm(g_state.active_comm, sizeof(g_state.active_comm), comm);
        pthread_cond_broadcast(&g_state_cond);
        pthread_mutex_unlock(&g_state_lock);

        if (comm[0]) {
            bpftune_log(LOG_NOTICE,
                        "Detected %s gaming profile (process: %s, pps: %d, variance: %ld%s%s)",
                        profile_name, comm, pps, variance,
                        ifname[0] ? ", interface: " : "",
                        ifname[0] ? ifname : "");
        } else {
            bpftune_log(LOG_NOTICE,
                        "Detected %s gaming profile (pps: %d, variance: %ld%s%s)",
                        profile_name, pps, variance,
                        ifname[0] ? ", interface: " : "",
                        ifname[0] ? ifname : "");
        }

        apply_profile(tuner, intensity, 0);
        apply_interface_tuning(ifindex, intensity);
        break;
    }

    case GAMING_SCENARIO_ENDED: {
        struct gaming_event_data data = {};
        char ifname[IF_NAMESIZE] = { 0 };
        char comm[GAMING_TUNER_COMM_LEN] = { 0 };
        char tracked_comm[GAMING_TUNER_COMM_LEN] = { 0 };
        const char *log_comm = NULL;
        int was_active;
        int pps;
        long variance;
        unsigned int ifindex;

        memcpy(&data, event->raw_data, sizeof(data));

        pps = (int)data.pps;
        variance = (long)data.variance;
        ifindex = data.ifindex;

        gaming_copy_comm(comm, sizeof(comm), data.comm);

        if (ifindex)
            if_indextoname(ifindex, ifname);

        pthread_mutex_lock(&g_state_lock);
        was_active = g_state.active;
        if (was_active) {
            g_state.current_pps = pps;
            if (ifindex) {
                g_state.active_ifindex = ifindex;
                if (ifname[0])
                    snprintf(g_state.active_ifname, sizeof(g_state.active_ifname), "%s", ifname);
            }
            g_state.active_ifname[sizeof(g_state.active_ifname) - 1] = '\0';
            gaming_copy_comm(tracked_comm, sizeof(tracked_comm), g_state.active_comm);
        }
        pthread_mutex_unlock(&g_state_lock);

        if (!was_active)
            break;

        if (tracked_comm[0])
            log_comm = tracked_comm;
        else if (comm[0])
            log_comm = comm;

        if (log_comm) {
            bpftune_log(LOG_DEBUG,
                        "Gaming traffic quiet (process: %s, pps: %d, variance: %ld%s%s); scheduling baseline restore",
                        log_comm, pps, variance,
                        ifname[0] ? ", interface: " : "",
                        ifname[0] ? ifname : "");
        } else {
            bpftune_log(LOG_DEBUG,
                        "Gaming traffic quiet (pps: %d, variance: %ld%s%s); scheduling baseline restore",
                        pps, variance,
                        ifname[0] ? ", interface: " : "",
                        ifname[0] ? ifname : "");
        }

        gaming_schedule_revert();
        break;
    }

    default:
        bpftune_log(LOG_DEBUG, "Unknown event scenario %u for tuner %s",
                    event->scenario_id, tuner->name);
        break;
    }
}
