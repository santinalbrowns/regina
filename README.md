# SysMon: System Event Monitoring Backend

## Overview
SysMon is a Wazuh-like system for monitoring system events across multiple devices. It provides real-time visibility into system activities, security alerts, and performance metrics, with a modern web dashboard for visualization and management.

## Features
- **Agent-based monitoring**: Collects events from multiple hosts (agents)
- **Event types**: Process start/end, logins, logouts, file changes, network connections, system boot/shutdown, security and performance alerts, and Suricata IDS/IPS alerts
- **Rule engine**: Customizable rules for generating alerts based on event patterns
- **Web dashboard**: Modern UI for viewing agents, events, alerts, and managing users
- **User management**: Admin/user roles, add/delete users
- **Suricata integration**: Ingests Suricata EVE JSON alerts for network security monitoring

## Architecture
- **Backend**: Python (Flask), SQLite database
- **Agent**: Python script that monitors system events and sends them to the server
- **Frontend**: Single-page dashboard rendered by Flask using Tailwind CSS and Chart.js
- **Suricata**: Open-source IDS/IPS, logs alerts to `/var/log/suricata/eve.json`

### Components
- `app.py`: Main server and dashboard
- `agent.py`: Example agent that collects and sends events
- `requirements.txt`: Python dependencies
- `install_suricata.sh`: Bash script to install and configure Suricata automatically

## Installation Guide

### 1. Clone the Repository
```bash
git clone https://github.com/santinalbrowns/regina.git
cd regina
```

### 2. Install Python Dependencies
It is recommended to use a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Install and Configure Suricata (Optional, for network security monitoring)
#### Option 1: Use the provided Bash script (Recommended)
```bash
sudo bash install_suricata.sh
```
This will automatically install and configure Suricata for your default network interface.

#### Option 2: Manual installation
Run the following commands on each agent you want to monitor with Suricata:
```bash
sudo apt-get update
sudo apt-get install -y suricata
sudo systemctl enable suricata
sudo systemctl start suricata
# Detect default interface
default_iface=$(ip route | grep default | awk '{print $5}' | head -n1)
sudo sed -i "s/^ *- interface: .*/  - interface: $default_iface/" /etc/suricata/suricata.yaml
sudo sed -i '/^ *- eve-log:/,/^ *- /{s/enabled: *no/enabled: yes/}' /etc/suricata/suricata.yaml
sudo systemctl restart suricata
```

### 4. Start the Server
```bash
python app.py flask
```
The dashboard will be available at [http://localhost:8080/dashboard](http://localhost:8080/dashboard)

### 5. Start an Agent (on each monitored host)
Edit `agent.py` if needed to point to your server, then run:
```bash
python agent.py
```

## Usage
- **Login**: Default admin user is `Regina` with password `pass1234`
- **Dashboard**: View system overview, recent events, alerts, and agent status
- **Alerts**: See triggered alerts and acknowledge them
- **Events**: Browse/search all collected events
- **Users**: (Admin only) Manage users

## How It Works
- **Agents** collect system and network events and send them to the server via HTTP.
- **Server** stores events in SQLite, evaluates them against rules, and generates alerts.
- **Dashboard** displays real-time data, charts, and tables for easy monitoring.
- **Rule Engine** matches event patterns (e.g., "High CPU Usage", "Suricata Alert") to trigger alerts.
- **Suricata** logs are ingested for network security events.

## Customization
- **Rules**: Add or modify rules in the server code (`_add_default_rules` in `app.py`).
- **Event types**: Extend `SystemMonitor` and `SystemEvent` for more event sources.
- **UI**: Edit the HTML/JS in `app.py` for dashboard customization.

## Contribution
Pull requests and issues are welcome! Please open an issue to discuss major changes.

## License
MIT License 