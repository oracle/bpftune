// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/*
 * Gaming Performance Tuner - eBPF detector
 * Identifies competitive gaming traffic patterns and notifies userspace.
 */

#include <bpftune/bpftune.bpf.h>
#include "gaming_tuner.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GAMING_INTENSITY_DWELL_NS (5ULL * 1000000000ULL)

struct gaming_stats {
    __u64 udp_packets;
    __u64 tracked_udp_packets;
    __u64 last_activity;
    __u32 current_pps;
    __u32 is_gaming;
    __u32 game_intensity;
    __u32 steady_periods;
    __u32 calm_periods;
    __u32 intensity_candidate;
    __u32 intensity_confidence;
    __u32 reported_intensity;
    __u32 pps_history[GAMING_TUNER_PPS_HISTORY];
    __u32 pps_history_idx;
    __u64 last_pps_update;
    __u32 pps_variance;
#ifndef BPFTUNE_LEGACY
    struct bpf_timer timeout_timer;
#endif
    __u32 active_ifindex;
    char current_comm[GAMING_TUNER_COMM_LEN];
    __u64 last_intensity_change;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct gaming_stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

static __always_inline __u32 calculate_smooth_pps(struct gaming_stats *stats)
{
    __u32 sum = 0;
    __u32 count = 0;

    for (int i = 0; i < (int)GAMING_TUNER_PPS_HISTORY; i++) {
        if (stats->pps_history[i]) {
            sum += stats->pps_history[i];
            count++;
        }
    }

    return count ? sum / count : 0;
}

static __always_inline __u32 calculate_pps_variance(struct gaming_stats *stats, __u32 avg)
{
    __u32 variance_sum = 0;
    __u32 count = 0;

    for (int i = 0; i < (int)GAMING_TUNER_PPS_HISTORY; i++) {
        __u32 value = stats->pps_history[i];
        if (!value)
            continue;

        if (value > avg)
            variance_sum += value - avg;
        else
            variance_sum += avg - value;
        count++;
    }

    return count ? variance_sum / count : 0;
}

static __always_inline void notify_userspace(__u32 scenario, __u32 intensity,
                                            __u32 pps, __u32 variance,
                                            __u32 ifindex,
                                            const char *comm)
{
    struct bpftune_event event = {};
    struct gaming_event_data *payload;

    event.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    event.tuner_id = tuner_id;
    event.scenario_id = scenario;
    payload = (struct gaming_event_data *)event.raw_data;
    payload->intensity = intensity;
    payload->pps = pps;
    payload->variance = variance;
    payload->ifindex = ifindex;

    if (comm) {
        for (int i = 0; i < GAMING_TUNER_COMM_LEN; i++) {
            payload->comm[i] = comm[i];
            if (!comm[i])
                break;
        }
    }

    bpf_ringbuf_output(&ring_buffer_map, &event, sizeof(event), 0);
}

#define GAMING_PPS_WINDOW_NS 1000000000ULL

#ifndef BPFTUNE_LEGACY
static __always_inline void gaming_timer_schedule(struct gaming_stats *stats, __u64 delay)
{
    if (!stats)
        return;

    bpf_timer_start(&stats->timeout_timer, delay, 0);
}

static int gaming_timeout_cb(void *map, int *key, struct gaming_stats *stats)
{
    __u64 now;
    __u64 inactivity;

    if (!stats || !stats->is_gaming)
        return 0;

    now = bpf_ktime_get_ns();
    if (!stats->last_activity) {
        gaming_timer_schedule(stats, GAMING_TUNER_TIMEOUT_NS);
        return 0;
    }

    inactivity = now - stats->last_activity;
    if (inactivity >= GAMING_TUNER_TIMEOUT_NS) {
        notify_userspace(GAMING_SCENARIO_ENDED,
                         stats->game_intensity,
                         stats->current_pps,
                         stats->pps_variance,
                         stats->active_ifindex,
                         stats->current_comm);
        stats->is_gaming = 0;
        stats->steady_periods = 0;
        stats->game_intensity = 0;
        stats->current_pps = 0;
        stats->pps_variance = 0;
        stats->current_comm[0] = '\0';
        stats->last_intensity_change = 0;
        return 0;
    }

    gaming_timer_schedule(stats, GAMING_TUNER_TIMEOUT_NS - inactivity);
    return 0;
}
#endif

static __always_inline void record_activity(struct gaming_stats *stats, __u64 now)
{
    if (!stats)
        return;

    stats->last_activity = now;
#ifndef BPFTUNE_LEGACY
    if (stats->is_gaming)
        gaming_timer_schedule(stats, GAMING_TUNER_TIMEOUT_NS);
#endif
}

static __always_inline void handle_pps_window(struct gaming_stats *stats, __u64 now);

static __always_inline __u16 gaming_sock_dport(const struct sock *sk)
{
    __u16 dport = 0;

    if (!sk)
        return 0;

    dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    return bpf_ntohs(dport);
}

static __always_inline void gaming_count_packet(struct gaming_stats *stats,
                                                __u64 now, __u64 len,
                                                __u16 dport)
{
    if (!stats)
        return;

    if (len <= GAMING_TUNER_UDP_MAX_SIZE) {
        stats->tracked_udp_packets++;

        if (now - stats->last_pps_update >= GAMING_PPS_WINDOW_NS)
            handle_pps_window(stats, now);
    }
}

static __always_inline __u32 gaming_determine_intensity(__u32 current,
                                                        __u32 pps)
{
    if (current >= 2) {
        if (pps <= GAMING_TUNER_INTENSE_LOW)
            return 1;
        return 2;
    }

    if (current == 1) {
        if (pps >= GAMING_TUNER_INTENSE_HIGH)
            return 2;
        if (pps <= GAMING_TUNER_COMP_LOW)
            return 0;
        return 1;
    }

    if (pps >= GAMING_TUNER_INTENSE_HIGH)
        return 2;
    if (pps >= GAMING_TUNER_COMP_HIGH)
        return 1;
    return 0;
}

static __always_inline void handle_pps_window(struct gaming_stats *stats, __u64 now)
{
    __u32 smooth_pps;
    __u32 variance;
    __u64 recent_packets;
    char current_comm[GAMING_TUNER_COMM_LEN] = {};

    stats->pps_history_idx = (stats->pps_history_idx + 1) % GAMING_TUNER_PPS_HISTORY;
    stats->pps_history[stats->pps_history_idx] = stats->tracked_udp_packets;

    smooth_pps = calculate_smooth_pps(stats);
    variance = calculate_pps_variance(stats, smooth_pps);

    recent_packets = stats->tracked_udp_packets;

    stats->current_pps = smooth_pps;
    stats->pps_variance = variance;
    stats->tracked_udp_packets = 0;
    stats->last_pps_update = now;

    if (bpf_get_current_comm(current_comm, sizeof(current_comm)) == 0) {
        __builtin_memset(stats->current_comm, 0, sizeof(stats->current_comm));
        for (int i = 0; i < GAMING_TUNER_COMM_LEN; i++) {
            stats->current_comm[i] = current_comm[i];
            if (!current_comm[i])
                break;
        }
    }

    if (!stats->is_gaming) {
        if (smooth_pps >= GAMING_TUNER_UDP_MIN_PPS) {
            __u32 variance_threshold = smooth_pps / 2;
            __u32 variance_rel;
            bool bursty = recent_packets >= (GAMING_TUNER_UDP_MIN_PPS * 2);

            if (variance_threshold < GAMING_TUNER_VARIANCE_MIN)
                variance_threshold = GAMING_TUNER_VARIANCE_MIN;

            variance_rel = (__u32)(((__u64)smooth_pps * GAMING_TUNER_VARIANCE_REL_NUM) /
                                   GAMING_TUNER_VARIANCE_REL_DEN);
            if (variance_rel < GAMING_TUNER_VARIANCE_MIN)
                variance_rel = GAMING_TUNER_VARIANCE_MIN;
            if (variance_threshold < variance_rel)
                variance_threshold = variance_rel;

            if (!bursty && smooth_pps < GAMING_TUNER_UDP_MIN_PPS + 3) {
                stats->steady_periods = 0;
                return;
            }

            if (variance <= variance_threshold || bursty)
                stats->steady_periods++;
            else
                stats->steady_periods = 0;

            if ((bursty && stats->steady_periods >= 2) ||
                (!bursty && stats->steady_periods >= 3)) {
                __u32 start_intensity;

                if (stats->current_comm[0] == '\0') {
                    stats->steady_periods = 0;
                    return;
                }

                stats->is_gaming = 1;
                stats->steady_periods = 0;
                stats->calm_periods = 0;

                start_intensity = gaming_determine_intensity(0, smooth_pps);
                stats->game_intensity = start_intensity;
                stats->reported_intensity = start_intensity;
                stats->intensity_candidate = start_intensity;
                stats->intensity_confidence = 1;

                notify_userspace(GAMING_SCENARIO_DETECTED,
                                 start_intensity,
                                 smooth_pps,
                                 variance,
                                 stats->active_ifindex,
                                 stats->current_comm);
                stats->last_intensity_change = now;
#ifndef BPFTUNE_LEGACY
                gaming_timer_schedule(stats, GAMING_TUNER_TIMEOUT_NS);
#endif
            }
        }
        return;
    }

#ifdef BPFTUNE_LEGACY
    if (now - stats->last_activity > GAMING_TUNER_TIMEOUT_NS) {
        notify_userspace(GAMING_SCENARIO_ENDED,
                         stats->game_intensity,
                         smooth_pps,
                         variance,
                         stats->active_ifindex,
                         stats->current_comm);
        stats->is_gaming = 0;
        stats->steady_periods = 0;
        stats->calm_periods = 0;
        stats->game_intensity = 0;
        stats->current_comm[0] = '\0';
        return;
    }
#else
    gaming_timer_schedule(stats, GAMING_TUNER_TIMEOUT_NS);
#endif

    if (smooth_pps <= GAMING_TUNER_IDLE_PPS)
        stats->calm_periods++;
    else
        stats->calm_periods = 0;

    if (stats->calm_periods >= 3) {
        notify_userspace(GAMING_SCENARIO_ENDED,
                         stats->game_intensity,
                         smooth_pps,
                         variance,
                         stats->active_ifindex,
                         stats->current_comm);
        stats->is_gaming = 0;
        stats->steady_periods = 0;
        stats->calm_periods = 0;
        stats->game_intensity = 0;
        stats->reported_intensity = 0;
        stats->intensity_candidate = 0;
        stats->intensity_confidence = 0;
        stats->current_comm[0] = '\0';
        stats->last_intensity_change = 0;
        return;
    }

    {
        __u32 candidate;

        candidate = gaming_determine_intensity(stats->reported_intensity, smooth_pps);

        if (candidate == 0 && stats->reported_intensity > 0 &&
            smooth_pps > GAMING_TUNER_IDLE_PPS)
            candidate = stats->reported_intensity;

        if (stats->current_comm[0] == '\0')
            return;

        if (candidate != stats->intensity_candidate) {
            stats->intensity_candidate = candidate;
            stats->intensity_confidence = 1;
        } else if (stats->intensity_confidence < 5) {
            stats->intensity_confidence++;
        }

        if (candidate != stats->reported_intensity) {
            __u32 required;
            __u64 since_change;

            since_change = stats->last_intensity_change ?
                           (now - stats->last_intensity_change) :
                           GAMING_INTENSITY_DWELL_NS;

            if (since_change < GAMING_INTENSITY_DWELL_NS)
                goto out;

            if (candidate > stats->reported_intensity)
                required = 3;
            else if (candidate == 0)
                required = 6;
            else
                required = 4;

            if (stats->intensity_confidence >= required) {
                stats->reported_intensity = candidate;
                stats->last_intensity_change = now;
                notify_userspace(GAMING_SCENARIO_DETECTED,
                                 candidate,
                                 smooth_pps,
                                 variance,
                                 stats->active_ifindex,
                                 stats->current_comm);
            }
        }
    }

out:
    stats->game_intensity = stats->reported_intensity;
}

BPF_FENTRY(udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u32 key = 0;
    struct gaming_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    __u64 now = bpf_ktime_get_ns();
    __u16 dport = gaming_sock_dport(sk);

    if (!stats)
        return 0;

    stats->udp_packets++;
    gaming_count_packet(stats, now, len, dport);

#ifndef BPFTUNE_LEGACY
    if (sk) {
        __u32 ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);

        if (!ifindex) {
            struct dst_entry *dst = BPF_CORE_READ(sk, sk_dst_cache);
            if (dst) {
                struct net_device *dev = BPF_CORE_READ(dst, dev);
                if (dev)
                    ifindex = BPF_CORE_READ(dev, ifindex);
            }
        }

        if (ifindex)
            stats->active_ifindex = ifindex;
    }
#endif

    record_activity(stats, now);

    return 0;
}

BPF_FENTRY(udp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len,
           int noblock, int flags, int *addr_len)
{
    __u32 key = 0;
    struct gaming_stats *stats;
    __u64 now;
    __u16 dport = gaming_sock_dport(sk);

    stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats)
        return 0;

    now = bpf_ktime_get_ns();

    if (len > 0)
        gaming_count_packet(stats, now, (__u64)len, dport);

    record_activity(stats, now);

    return 0;
}

BPF_FENTRY(inet_create, struct net *net, struct socket *sock, int protocol, int kern)
{
    __u32 key = 0;
    struct gaming_stats *stats = bpf_map_lookup_elem(&stats_map, &key);

    if (!stats)
        return 0;

    if (!stats->last_pps_update) {
        stats->last_pps_update = bpf_ktime_get_ns();
#ifndef BPFTUNE_LEGACY
        bpf_timer_init(&stats->timeout_timer, &stats_map, 0);
        bpf_timer_set_callback(&stats->timeout_timer, gaming_timeout_cb);
#endif
    }

    return 0;
}

char __license[] SEC("license") = "GPL";
