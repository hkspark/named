for user in root redis; do
    usermod -s /usr/sbin/nologin $user
done
