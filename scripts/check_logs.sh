for log in ssh nginx flask redis redis-server; do
    systemd-journald -u $log
    if file /var/log/$log; then
        less /var/log/$log/*.log
    fi
done

