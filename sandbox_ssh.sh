```bash
#!/bin/bash
#Jails whatever user that runs it, doesnt stop user from making files or editing with vi
#exit will exit the program and send back to directory it ran from

# Usage: sudo ./setup_jail.sh username

USER_NAME="$1"
JAIL_DIR="/home/$USER_NAME"
BIN_DIR="$JAIL_DIR/bin"
LIB_DIR="$JAIL_DIR/lib"
LIB64_DIR="$JAIL_DIR/lib64"

if [ -z "$USER_NAME" ]; then
    echo "Usage: $0 username"
    exit 1
fi

echo "[+] Creating jail for user: $USER_NAME"

# Create directories
mkdir -p $BIN_DIR $LIB_DIR $LIB64_DIR $JAIL_DIR/files

# Fix ownership (CRITICAL)
chown root:root $JAIL_DIR
chmod 555 $JAIL_DIR

# Create user-writable directory
chown $USER_NAME:$USER_NAME $JAIL_DIR/files

# Function to copy binaries and dependencies
copy_binary() {
    BIN="$1"
    echo "[+] Copying $BIN"

    cp "$BIN" "$BIN_DIR"

    # Copy dependencies
    ldd "$BIN" | grep -o '/[^ ]*' | while read -r LIB; do
        DEST="$JAIL_DIR$(dirname $LIB)"
        mkdir -p "$DEST"
        cp "$LIB" "$DEST"
    done
}

# Add allowed commands here
ALLOWED_CMDS=(
#Might have to change /bin/bash to /bin/rbash to ensure restriction/no escape
    /bin/rbash
    /bin/ls
    /bin/cat
    /bin/echo
)

for CMD in "${ALLOWED_CMDS[@]}"; do
    copy_binary "$CMD"
done

# Create basic /dev files
mkdir -p $JAIL_DIR/dev
mknod -m 666 $JAIL_DIR/dev/null c 1 3
mknod -m 666 $JAIL_DIR/dev/zero c 1 5
mknod -m 666 $JAIL_DIR/dev/tty c 5 0

# Create restricted bash (rbash)
ln -sf /bin/bash $BIN_DIR/rbash

# Set PATH restriction
echo 'export PATH=/bin' > $JAIL_DIR/files/.bash_profile

# Ensure correct ownership inside jail
chown -R root:root $BIN_DIR $LIB_DIR $LIB64_DIR $JAIL_DIR/dev

echo "[+] Jail setup complete for $USER_NAME"
echo "[!] Make sure sshd_config contains:"
echo "Match User $USER_NAME"
echo "    ChrootDirectory $JAIL_DIR"
echo "    ForceCommand /bin/rbash"
```
