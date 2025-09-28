/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Gaming Performance Tuner definitions shared between user and BPF code.
 */

#ifndef GAMING_TUNER_H
#define GAMING_TUNER_H

#include <bpftune/bpftune.h>

#ifndef GAMING_TUNER_COMM_LEN
#ifdef TASK_COMM_LEN
#define GAMING_TUNER_COMM_LEN TASK_COMM_LEN
#else
#define GAMING_TUNER_COMM_LEN 16
#endif
#endif

#define GAMING_TUNER_FOR_EACH_IGNORE(ENTRY) \
	ENTRY("discord") \
	ENTRY("discordcanary") \
	ENTRY("steam") \
	ENTRY("steamwebhelper") \
	ENTRY("steamservice") \
	ENTRY("avahi-daemon") \
	ENTRY("qbittorrent") \
	ENTRY("qbittorrent-nox") \
	ENTRY("transmission") \
	ENTRY("transmission-da") \
	ENTRY("transmission-gt") \
	ENTRY("deluge-gtk") \
	ENTRY("deluged") \
	ENTRY("deluge-web") \
	ENTRY("rtorrent") \
	ENTRY("aria2c") \
	ENTRY("ktorrent") \
	ENTRY("utp::*") \
	ENTRY("ipc:csteam*") \
	ENTRY("chrome*") \
	ENTRY("systemd-resolve") \
	ENTRY("tokio-runtime-w")

#define GAMING_TUNER_FOR_EACH_LAUNCHER(ENTRY) \
	ENTRY("steam") \
	ENTRY("steamwebhelper") \
	ENTRY("pressure-vessel") \
	ENTRY("gamescope") \
	ENTRY("gamemoderun") \
	ENTRY("gamemoded") \
	ENTRY("heroic") \
	ENTRY("lutris") \
	ENTRY("legendary") \
	ENTRY("bottles") \
	ENTRY("mangohud")

/* Number of samples stored when smoothing packets-per-second estimates. */
#define GAMING_TUNER_PPS_HISTORY 8

/* UDP payload threshold when counting UDP packets for gaming detection. */
#define GAMING_TUNER_UDP_MAX_SIZE 1500

/* Minimum packets-per-second before we treat traffic as gaming related. */
#define GAMING_TUNER_UDP_MIN_PPS 25

/* Smoothed PPS thresholds used to select competitive vs intense profiles. */
#define GAMING_TUNER_COMPETITIVE_PPS 70
#define GAMING_TUNER_INTENSE_PPS 140

/* Threshold below which we consider traffic idle and start rollback countdown. */
#define GAMING_TUNER_IDLE_PPS 10

#define GAMING_TUNER_INTENSITY_MARGIN 15
#define GAMING_TUNER_COMP_HIGH (GAMING_TUNER_COMPETITIVE_PPS + GAMING_TUNER_INTENSITY_MARGIN)
#define GAMING_TUNER_COMP_LOW \
	((GAMING_TUNER_COMPETITIVE_PPS > GAMING_TUNER_INTENSITY_MARGIN) ? \
	 (GAMING_TUNER_COMPETITIVE_PPS - GAMING_TUNER_INTENSITY_MARGIN) : \
	 GAMING_TUNER_UDP_MIN_PPS)
#define GAMING_TUNER_INTENSE_HIGH (GAMING_TUNER_INTENSE_PPS + GAMING_TUNER_INTENSITY_MARGIN)
#define GAMING_TUNER_INTENSE_LOW \
	((GAMING_TUNER_INTENSE_PPS > GAMING_TUNER_INTENSITY_MARGIN) ? \
	 (GAMING_TUNER_INTENSE_PPS - GAMING_TUNER_INTENSITY_MARGIN) : \
	 GAMING_TUNER_COMP_HIGH)

/* Nanoseconds without activity before declaring the session finished. */
#define GAMING_TUNER_TIMEOUT_NS (5ULL * 1000000000ULL)

enum gaming_tunables {
	GAMING_TUNABLE_RMEM_DEFAULT,
	GAMING_TUNABLE_RMEM_MAX,
	GAMING_TUNABLE_WMEM_DEFAULT,
	GAMING_TUNABLE_WMEM_MAX,
	GAMING_TUNABLE_NETDEV_MAX_BACKLOG,
	GAMING_TUNABLE_NETDEV_BUDGET,
	GAMING_TUNABLE_NETDEV_BUDGET_USECS,
	GAMING_TUNABLE_UDP_MEM,
	GAMING_TUNABLE_BUSY_READ,
	GAMING_TUNABLE_BUSY_POLL,
	GAMING_TUNABLE_UDP_EARLY_DEMUX,
	GAMING_TUNABLE_COUNT,
};

enum gaming_scenarios {
	GAMING_SCENARIO_DETECTED,
	GAMING_SCENARIO_ENDED,
};

enum gaming_tuner_event_index {
	GAMING_TUNER_EVENT_INTENSITY,
	GAMING_TUNER_EVENT_PPS,
	GAMING_TUNER_EVENT_VARIANCE,
	GAMING_TUNER_EVENT_IFINDEX,
	GAMING_TUNER_EVENT_COUNT,
};

struct gaming_event_data {
	__u32 intensity;
	__u32 pps;
	__u32 variance;
	__u32 ifindex;
	char comm[GAMING_TUNER_COMM_LEN];
};

#endif /* GAMING_TUNER_H */
#define GAMING_TUNER_FOR_EACH_LAUNCHER_CMD(ENTRY) \
	ENTRY("steamapps/") \
	ENTRY("SteamLaunch") \
	ENTRY("PressureVessel") \
	ENTRY("pressure-vessel") \
	ENTRY("gamescope") \
	ENTRY("gamemoderun") \
	ENTRY("gamemode") \
	ENTRY("heroic") \
	ENTRY("lutris") \
	ENTRY("legendary") \
	ENTRY("bottles") \
	ENTRY("mangohud") \
	ENTRY("proton")
