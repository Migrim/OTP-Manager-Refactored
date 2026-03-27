#!/bin/bash
set -e

INSTALL_DIR="/opt/otp-manager"
REPO="https://github.com/Migrim/OTP-Manager-Refactored/archive/refs/heads/main.zip"
PORT=7440

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root (use sudo bash install.sh)"
    exit 1
fi

echo "=== OTP Manager Installer ==="

apt-get update -y
apt-get install -y python3 python3-pip tmux unzip curl

echo "Downloading OTP Manager..."
mkdir -p "$INSTALL_DIR"
curl -L "$REPO" -o /tmp/otp.zip
unzip -o /tmp/otp.zip -d /tmp/otp-extract
cp -r /tmp/otp-extract/OTP-Manager-Refactored-main/. "$INSTALL_DIR/"
rm -rf /tmp/otp.zip /tmp/otp-extract

pip3 install --break-system-packages flask flask-bcrypt reportlab pyotp "qrcode[pil]" 2>/dev/null \
    || pip3 install flask flask-bcrypt reportlab pyotp "qrcode[pil]"

cat > /root/start-otp.sh << 'EOF'
#!/bin/bash
tmux kill-session -t otp 2>/dev/null || true
tmux new-session -d -s otp -c /opt/otp-manager 'python3 start.py'
EOF
chmod +x /root/start-otp.sh

cat > /etc/systemd/system/otp-manager.service << 'EOF'
[Unit]
Description=OTP Manager
After=network.target

[Service]
Type=forking
User=root
ExecStart=/root/start-otp.sh
ExecStop=/usr/bin/tmux kill-session -t otp
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable otp-manager
systemctl start otp-manager

if ! grep -q "tmux attach -t otp" /root/.bashrc; then
    cat >> /root/.bashrc << 'EOF'

# Auto-attach to OTP Manager on login
if [ -z "$TMUX" ] && [ -n "$SSH_CONNECTION" ]; then
    tmux attach -t otp 2>/dev/null || true
fi
EOF
fi

SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "=== OTP Manager installed successfully! ==="
echo ""
echo "  Access it in your browser at:"
echo "  http://$SERVER_IP:$PORT"
echo ""
echo "  SSH login will drop you into the TUI automatically."
echo "  Detach with Ctrl+B then D to return to shell."
echo ""
echo "Server will restart in 10 seconds... (Ctrl+C to cancel)"
for i in $(seq 10 -1 1); do
    echo -ne "\rRestarting in $i seconds...  "
    sleep 1
done
echo -e "\rRestarting now!              "
reboot
