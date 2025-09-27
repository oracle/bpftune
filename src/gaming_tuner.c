/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Gaming Performance Tuner - userspace controller
 * Applies network tuning profiles when the eBPF detector reports activity.
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <bpftune/libbpftune.h>
#include <bpftune/bpftune.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

    bpftune_log(LOG_NOTICE,
                "Gaming traffic paused; will restore baseline if still quiet after %d seconds",
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
        pthread_cond_broadcast(&g_state_cond);
        pthread_mutex_unlock(&g_state_lock);
        if (restored) {
            const char *details = summary_buffer_is_empty(&summary) ?
                                  "baseline already active" :
                                  summary_buffer_text(&summary);
            bpftune_log(LOG_NOTICE, "Restored gaming tunables: %s%s",
                        details,
                        summary_buffer_truncated(&summary) ? " ..." : "");
        } else {
            bpftune_log(LOG_NOTICE, "Gaming profile settings already at baseline");
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
        int intensity = event->update[GAMING_TUNER_EVENT_INTENSITY].new[0];
        int pps = event->update[GAMING_TUNER_EVENT_PPS].new[0];
        long variance = event->update[GAMING_TUNER_EVENT_VARIANCE].new[0];
        unsigned int ifindex = event->update[GAMING_TUNER_EVENT_IFINDEX].new[0];
        char ifname[IF_NAMESIZE] = { 0 };
        size_t profile_idx = clamp_profile_index(intensity);
        const char *profile_name = profiles[profile_idx].name;

        if (ifindex)
            if_indextoname(ifindex, ifname);

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
        pthread_cond_broadcast(&g_state_cond);
        pthread_mutex_unlock(&g_state_lock);

        bpftune_log(LOG_NOTICE,
                    "Detected %s gaming profile (pps: %d, variance: %ld%s%s)",
                    profile_name, pps, variance,
                    ifname[0] ? ", interface: " : "",
                    ifname[0] ? ifname : "");

        apply_profile(tuner, intensity, 0);
        apply_interface_tuning(ifindex, intensity);
        break;
    }

    case GAMING_SCENARIO_ENDED: {
        int pps = event->update[GAMING_TUNER_EVENT_PPS].new[0];
        long variance = event->update[GAMING_TUNER_EVENT_VARIANCE].new[0];
        unsigned int ifindex = event->update[GAMING_TUNER_EVENT_IFINDEX].new[0];
        char ifname[IF_NAMESIZE] = { 0 };
        int should_schedule;

        if (ifindex)
            if_indextoname(ifindex, ifname);

        pthread_mutex_lock(&g_state_lock);
        g_state.current_pps = pps;
        if (ifindex) {
            g_state.active_ifindex = ifindex;
            if (ifname[0])
                snprintf(g_state.active_ifname, sizeof(g_state.active_ifname), "%s", ifname);
        }
        g_state.active_ifname[sizeof(g_state.active_ifname) - 1] = '\0';
        should_schedule = g_state.active;
        pthread_mutex_unlock(&g_state_lock);

        bpftune_log(LOG_NOTICE,
                    "Gaming traffic quiet (pps: %d, variance: %ld%s%s)%s",
                    pps, variance,
                    ifname[0] ? ", interface: " : "",
                    ifname[0] ? ifname : "",
                    should_schedule ?
                        "; scheduling baseline restore" :
                        "; nothing active to revert");

        if (should_schedule) {
            gaming_schedule_revert();
            bpftune_log(LOG_NOTICE,
                        "Baseline restore will run if still quiet after %d seconds",
                        GAMING_REVERT_GRACE_SECONDS);
        }
        break;
    }

    default:
        bpftune_log(LOG_DEBUG, "Unknown event scenario %u for tuner %s",
                    event->scenario_id, tuner->name);
        break;
    }
}
