#!/bin/bash

echo "Removing cron jobs..."

# Remove user cron jobs
rm -rf /var/spool/cron/*
rm -rf /var/spool/cron/crontabs/*

# Remove system cron jobs
rm -f /etc/cron.d/*
rm -f /etc/cron.daily/*
rm -f /etc/cron.hourly/*
rm -f /etc/cron.weekly/*
rm -f /etc/cron.monthly/*

echo "Locking cron directories..."

chmod 000 /var/spool/cron
chmod 000 /var/spool/cron/crontabs
chmod 000 /etc/cron.d

echo "Cron persistence blocked."
