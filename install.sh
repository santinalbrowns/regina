#!/bin/bash

set -e

# 1. Install Suricata
echo "Updating package lists..."
sudo apt-get update

echo "Installing Suricata..."
sudo apt-get install -y suricata

# 2. Enable and start Suricata service
echo "Enabling and starting Suricata service..."
sudo systemctl enable suricata
sudo systemctl start suricata

# 3. Detect default network interface
DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "Detected default network interface: $DEFAULT_IFACE"

# 4. Configure Suricata to monitor the default interface
echo "Configuring Suricata to monitor interface $DEFAULT_IFACE..."
sudo sed -i "s/^ *- interface: .*/  - interface: $DEFAULT_IFACE/" /etc/suricata/suricata.yaml

# 5. Ensure EVE JSON output is enabled
echo "Ensuring EVE JSON output is enabled..."
sudo sed -i '/^ *- eve-log:/,/^ *- /{s/enabled: *no/enabled: yes/}' /etc/suricata/suricata.yaml

# 6. Restart Suricata to apply changes
echo "Restarting Suricata..."
sudo systemctl restart suricata

# 7. Show status
echo "Suricata status:"
sudo systemctl status suricata --no-pager

echo "Suricata installation and configuration complete!"
echo "EVE JSON logs will be available at /var/log/suricata/eve.json"