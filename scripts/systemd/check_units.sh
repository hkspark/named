for unit_type in path service socket timer; do
    diff  <(systemctl list-unit-files --type=$unit_type --no-legend | awk '{print $1, $2}' | column -t) systemd/units/${unit_type}s.list
done
