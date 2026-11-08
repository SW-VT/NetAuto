#!/bin/bash
# Einmalige Einrichtung für NetAuto.
#   Installieren:  sudo ./setup.sh
#   Entfernen:     sudo ./setup.sh remove
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Bitte mit sudo starten: sudo ./setup.sh"
  exit 1
fi

SUDOERS=/etc/sudoers.d/netauto
PLIST=/Library/LaunchDaemons/local.netauto.bpf.plist

if [ "$1" = "remove" ]; then
  launchctl bootout system "$PLIST" 2>/dev/null || true
  rm -f "$SUDOERS" "$PLIST"
  echo "Entfernt. (Die Rechte auf /dev/bpf* gelten bis zum nächsten Neustart.)"
  exit 0
fi

USER_NAME="${SUDO_USER:-$(logname)}"

# 1) networksetup ohne Passwortabfrage (nur dieses eine Programm)
TMP=$(mktemp)
echo "$USER_NAME ALL=(root) NOPASSWD: /usr/sbin/networksetup" > "$TMP"
visudo -cf "$TMP"
install -m 0440 -o root -g wheel "$TMP" "$SUDOERS"
rm -f "$TMP"

# 2) Paket-Mitschnitt (tcpdump) ohne root: Admin-Gruppe darf /dev/bpf* lesen, auch nach Neustart
cat > "$PLIST" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>local.netauto.bpf</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>chgrp admin /dev/bpf*; chmod 660 /dev/bpf*</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
EOF
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
chgrp admin /dev/bpf*; chmod 660 /dev/bpf*

echo "Fertig. NetAuto kann jetzt Adapter umstellen und am Kabel mithören."
