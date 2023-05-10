================
BPFTUNE-SYSCTL
================
-------------------------------------------------------------------------------
sysctl bpftune plugin for monitoring sysctl settings
-------------------------------------------------------------------------------

:Manual section: 8


DESCRIPTION
===========
        The sysctl tuner watches for administrator-driven sysctl settings,
        and disables tuners that could collide with them.

        Each tuner declares which sysctls it operates on, and if we see a sysctl
        setting that collides with one of our managed sysctls, the associated tuner
        is disabled.  bpftune must be restarted to re-enable it.

        Intent is to get out of the way of the active administrator.

