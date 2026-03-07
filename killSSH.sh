#!/bin/bash

echo "Terminating all SSH sessions..."

# Find sshd session processes and kill them
pkill -f "sshd:"

echo "All SSH sessions terminated."
