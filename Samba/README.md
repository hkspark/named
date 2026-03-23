# CDt Blue Team - Samba Bundle

This folder is a “bundle” version of your existing scripts tuned for a **LAMP stack with Samba** scenario.

## What was copied
- `monitoring/linux_monitor.sh`
- `sandbox_ssh.sh` + `sandbox_sshd_config`
- all scripts from `Bash Scripts/*.sh` (copied into `Samba/Bash Scripts/`)

## What was tuned for LAMP + Samba
- `Samba/Bash Scripts/closeUnecessaryPorts.sh`
  - opens `22/tcp`, `80/tcp`, `443/tcp`
  - opens SMB ports: `139/tcp`, `445/tcp`
  - allows NetBIOS discovery: `137/udp`, `138/udp`
- `Samba/Bash Scripts/killProcesses.sh`
  - whitelist updated to keep:
    - `apache2`
    - `php-fpm` (plus `php-fpm*`)
    - `mysqld` / `mariadbd`
    - `smbd` / `nmbd`
  - removes the FTP-specific `vsftpd` allowlist entry

## Notes
- This bundle only copies scripts; it does not schedule or execute anything automatically.
- `sandbox_ssh.sh` in this repo includes content that may need cleanup before it can be executed directly (it appears to contain markdown code fences in the source).

