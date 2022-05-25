# sysctl tuner

The sysctl tuner watches for administrator-driven sysctl settings
and disables tuners that could collide with them.

# Algorithm

Each tuner declares which sysctls it operates on, and if we see
a sysctl setting that collides with one of our managed sysctls,
the associated tuner is disabled.

# Mechanics

We use a sysctl BPF program and send an event to userspace on
sysctl setting, so we can then iterate over tuners to find if
it is managed by us.
