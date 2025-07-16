import requests
import json
import uuid
import platform
import socket
import time
import logging
import os
import hashlib
import psutil
from app import MonitoringAgent, SystemMonitor

logger = logging.getLogger(__name__)


class NetworkedMonitoringAgent(MonitoringAgent):
    def __init__(self, server_host: str = "localhost", server_port: int = 8080):
        # Generate a stable agent ID based on hostname and MAC address
        hostname = platform.node()
        mac = self._get_primary_mac()
        base_id = f"{hostname}-{mac}"
        self.agent_id = hashlib.sha256(base_id.encode()).hexdigest()
        self.server_host = server_host
        self.server_port = server_port
        self.monitor = SystemMonitor(self.agent_id)
        self.running = False
        # No db_manager

    def _get_primary_mac(self):
        # Use psutil to get the first non-loopback MAC address
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK and addr.address != '00:00:00:00:00:00':
                    if not iface.lower().startswith('lo'):
                        return addr.address
        # Fallback to uuid if no MAC found
        return uuid.getnode()

    def _register_with_server(self):
        """Register this agent with the monitoring server via HTTP"""
        try:
            registration_data = {
                'agent_id': self.agent_id,
                'hostname': platform.node(),
                'ip_address': socket.gethostbyname(socket.gethostname()),
                'os_info': f"{platform.system()} {platform.release()}",
                'version': "1.0.0"
            }
            url = f"http://{self.server_host}:{self.server_port}/register_agent"
            resp = requests.post(url, json=registration_data, timeout=5)
            if resp.status_code == 200:
                logger.info(f"Registered agent via HTTP: {registration_data}")
            else:
                logger.error(f"Failed to register agent via HTTP: {resp.text}")
        except Exception as e:
            logger.error(f"Failed to register with server: {e}")

    def _process_events(self):
        """Process events from monitors and send to server via HTTP"""
        # Start all monitor generators
        monitor_generators = []
        for monitor_name in ['process', 'performance', 'network', 'suricata']:
            monitor_method = getattr(self.monitor, f'_monitor_{monitor_name}', None)
            if monitor_method:
                monitor_generators.append(monitor_method())
        while self.running:
            try:
                for gen in monitor_generators:
                    try:
                        event = next(gen)
                        # Convert event to dict for JSON
                        event_dict = event.to_dict()
                        # Send event to server
                        url = f"http://{self.server_host}:{self.server_port}/submit_event"
                        resp = requests.post(url, json=event_dict, timeout=5)
                        if resp.status_code == 200:
                            logger.info(f"Event sent: {event.title}")
                        else:
                            logger.error(f"Failed to send event: {resp.text}")
                    except StopIteration:
                        continue
                    except Exception as e:
                        logger.error(f"Error sending event: {e}")
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error processing events: {e}")
                time.sleep(5)

# Use the networked agent
agent = NetworkedMonitoringAgent(server_host="localhost", server_port=8080)
agent.start()