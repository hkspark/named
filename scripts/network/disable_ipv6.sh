echo "net.ipv6.conf.all.disable_ipv6 = 1" | tee /etc/sysctl.d/00-disable-ipv6.conf
sysctl -p /etc/sysctl.d/00-disable-ipv6.conf
