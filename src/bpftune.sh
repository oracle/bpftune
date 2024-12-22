#!/bin/sh

### BEGIN INIT INFO
# Provides:          bpftune
# Required-Start:    $network $local_fs $remote_fs
# Required-Stop:     $network $local_fs $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Should-Start:      $syslog
# Should-Stop:       $syslog
# Short-Description: BPF auto-tuning daemon (bpftune)
# Description: BPF-based auto-tuning of system parameters
### END INIT INFO

NAME="bpftune"
DESC="BPF-based auto-tuning of system parameters"
DAEMON=/usr/sbin/bpftune
PIDFILE=/var/run/bpftune.lock

test -x $DAEMON || exit 0
. /lib/lsb/init-functions

BPFTUNE_START_ARGS="--daemon"
BPFTUNE_PID=$(pidof bpftune)

case $1 in
  start)
      log_daemon_msg "Starting $NAME" "$NAME"
      start-stop-daemon --start --quiet --oknodo --exec $DAEMON -- $BPFTUNE_START_ARGS
      log_end_msg $?
  ;;

  stop)
    log_daemon_msg "Stopping $DESC" "$NAME"
    start-stop-daemon --stop --quiet --pid $BPFTUNE_PID
    log_end_msg $?
  ;;

  restart)
    $0 stop
    sleep 2
    $0 start
  ;;

  force-reload)
    /etc/init.d/bpftune.sh restart
  ;;

  status)
    status_of_proc /usr/bin/$NAME $NAME
  ;;

  *)
    echo "Usage: /etc/init.d/bpftune.sh {start|stop|restart|force-reload|status}"
    exit 1
  ;;
esac

# End of file
