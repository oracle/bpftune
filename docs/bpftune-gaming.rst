# Gaming tuner profile guide

The gaming tuner watches outgoing UDP traffic (≤1500 byte payloads) and
counts packets-per-second. If traffic stays above ~25 PPS for two sampling
windows with stable variance, the tuner classifies the session and applies
one of three profiles:

- **CASUAL** – Keeps socket defaults at 262 KB, backlog at 5 K, budgets modest,
  and busy-read/busy-poll around 25 µs. Suitable for lighter multiplayer or
  machines where background work still matters.
- **COMPETITIVE** – Raises rmem/wmem limits to 16 MB, bumps NAPI budgets, and
  shortens interrupt coalescing for twitch shooters or MOBAs on mainstream
  hardware.
- **INTENSE** – Pushes UDP/TCP caps to ~33 MB, maximizes NAPI budgets, and
  keeps NIC interrupts as immediate as the driver allows. Use for VR streaming,
  LAN events, or when squeezing the absolute lowest latency from a well-sized
  system.

When traffic quiets for ~10 s the tuner rolls every sysctl back to its cached
baseline and logs the restoration. If a system feels resource constrained,
drop down one profile tier or adjust the busy poll/read tunables to ~15–25 µs
before rebuilding the gaming tuner shared object.

The detection thresholds live in `src/gaming_tuner.h` (`GAMING_TUNER_UDP_MAX_SIZE`
and `GAMING_TUNER_UDP_MIN_PPS`). They can be tuned and rebuilt if a title has
unusual packet sizing or pacing requirements.
