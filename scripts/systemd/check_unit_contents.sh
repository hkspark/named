for unit in $(ls -R1d systemd/units/*/*); do
    if ! diff -yq <(systemctl cat $(echo $unit | sed "s|.*/||")) $unit; then
        echo $unit | sed "s|.*/||" > systemd/diffs.list
    fi
done
