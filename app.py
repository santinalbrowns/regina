#!/usr/bin/env python3
"""
System Event Monitoring Backend
A Wazuh-like system for monitoring system events across multiple devices
"""

import sqlite3
import json
import hashlib
import threading
import time
import socket
import ssl
import logging
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
import uuid
import os
import psutil
import platform
import subprocess
import re
from pathlib import Path
import flask
from flask import Flask, request, jsonify, send_from_directory, render_template_string, session, redirect, url_for
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EventType(Enum):
    FILE_CHANGE = "file_change"
    PROCESS_START = "process_start"
    PROCESS_END = "process_end"
    LOGIN = "login"
    LOGOUT = "logout"
    NETWORK_CONNECTION = "network_connection"
    SYSTEM_BOOT = "system_boot"
    SYSTEM_SHUTDOWN = "system_shutdown"
    SECURITY_ALERT = "security_alert"
    PERFORMANCE_ALERT = "performance_alert"
    CUSTOM = "custom"

class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class SystemEvent:
    id: str
    agent_id: str
    hostname: str
    timestamp: datetime
    event_type: EventType
    severity: Severity
    title: str
    description: str
    source: str
    data: Dict[str, Any]
    hash: str = ""
    
    def __post_init__(self):
        if not self.hash:
            self.hash = self._generate_hash()
    
    def _generate_hash(self) -> str:
        """Generate a hash for the event to detect duplicates"""
        content = f"{self.agent_id}{self.timestamp}{self.event_type.value}{self.title}{self.description}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'agent_id': self.agent_id,
            'hostname': self.hostname,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'source': self.source,
            'data': json.dumps(self.data),
            'hash': self.hash
        }

class DatabaseManager:
    def __init__(self, db_path: str = "monitoring.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    source TEXT NOT NULL,
                    data TEXT,
                    hash TEXT UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Agents table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    os_info TEXT,
                    version TEXT,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Rules table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rules (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    pattern TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    message TEXT NOT NULL,
                    acknowledged BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (event_id) REFERENCES events (id),
                    FOREIGN KEY (rule_id) REFERENCES rules (id)
                )
            ''')
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events(agent_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_agents_hostname ON agents(hostname)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts(event_id)')
            
            conn.commit()
    
    def store_event(self, event: SystemEvent) -> bool:
        """Store an event in the database"""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR IGNORE INTO events 
                        (id, agent_id, hostname, timestamp, event_type, severity, 
                         title, description, source, data, hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        event.id, event.agent_id, event.hostname, 
                        event.timestamp.isoformat(), event.event_type.value,
                        event.severity.value, event.title, event.description,
                        event.source, json.dumps(event.data), event.hash
                    ))
                    conn.commit()
                    return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Error storing event: {e}")
                return False
    
    def get_events(self, agent_id: str = None, event_type: str = None, 
                   severity: int = None, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Retrieve events with optional filtering"""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    query = "SELECT * FROM events WHERE 1=1"
                    params = []
                    
                    if agent_id:
                        query += " AND agent_id = ?"
                        params.append(agent_id)
                    
                    if event_type:
                        query += " AND event_type = ?"
                        params.append(event_type)
                    
                    if severity:
                        query += " AND severity >= ?"
                        params.append(severity)
                    
                    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                    params.extend([limit, offset])
                    
                    cursor.execute(query, params)
                    
                    columns = [desc[0] for desc in cursor.description]
                    events = []
                    for row in cursor.fetchall():
                        event_dict = dict(zip(columns, row))
                        if event_dict['data']:
                            event_dict['data'] = json.loads(event_dict['data'])
                        events.append(event_dict)
                    
                    return events
            except Exception as e:
                logger.error(f"Error retrieving events: {e}")
                return []
    
    def register_agent(self, agent_id: str, hostname: str, ip_address: str, 
                      os_info: str, version: str) -> bool:
        """Register or update an agent"""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR REPLACE INTO agents 
                        (id, hostname, ip_address, os_info, version, last_seen, status)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 'active')
                    ''', (agent_id, hostname, ip_address, os_info, version))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Error registering agent: {e}")
                return False
    
    def update_agent_status(self, agent_id: str, status: str = 'active') -> bool:
        """Update agent last seen timestamp and status"""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE agents 
                        SET last_seen = CURRENT_TIMESTAMP, status = ?
                        WHERE id = ?
                    ''', (status, agent_id))
                    conn.commit()
                    return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Error updating agent status: {e}")
                return False
    
    def get_agents(self) -> List[Dict]:
        """Get all registered agents"""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT * FROM agents ORDER BY hostname')
                    
                    columns = [desc[0] for desc in cursor.description]
                    agents = []
                    for row in cursor.fetchall():
                        agents.append(dict(zip(columns, row)))
                    
                    return agents
            except Exception as e:
                logger.error(f"Error retrieving agents: {e}")
                return []

    def get_users(self):
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT id, username, role, created_at FROM users ORDER BY username')
                    columns = [desc[0] for desc in cursor.description]
                    users = [dict(zip(columns, row)) for row in cursor.fetchall()]
                    return users
            except Exception as e:
                logger.error(f"Error retrieving users: {e}")
                return []
    def add_user(self, username, password_hash, role='user'):
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    user_id = str(uuid.uuid4())
                    cursor.execute('INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)',
                                   (user_id, username, password_hash, role))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Error adding user: {e}")
                return False
    def delete_user(self, user_id):
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
                    conn.commit()
                    return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Error deleting user: {e}")
                return False

class RuleEngine:
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.rules = {}
        self.load_rules()
    
    def load_rules(self):
        """Load rules from database"""
        with sqlite3.connect(self.db_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM rules WHERE enabled = TRUE')
            
            for row in cursor.fetchall():
                rule_id, name, description, pattern, severity, enabled, created_at = row
                self.rules[rule_id] = {
                    'name': name,
                    'description': description,
                    'pattern': pattern,
                    'severity': severity
                }
    
    def add_rule(self, name: str, description: str, pattern: str, severity: int) -> str:
        """Add a new rule"""
        rule_id = str(uuid.uuid4())
        
        with sqlite3.connect(self.db_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO rules (id, name, description, pattern, severity, enabled)
                VALUES (?, ?, ?, ?, ?, TRUE)
            ''', (rule_id, name, description, pattern, severity))
            conn.commit()
        
        self.rules[rule_id] = {
            'name': name,
            'description': description,
            'pattern': pattern,
            'severity': severity
        }
        
        return rule_id
    
    def evaluate_event(self, event: SystemEvent) -> List[Dict]:
        """Evaluate an event against all rules"""
        alerts = []
        
        for rule_id, rule in self.rules.items():
            if self._matches_rule(event, rule):
                alert = {
                    'id': str(uuid.uuid4()),
                    'event_id': event.id,
                    'rule_id': rule_id,
                    'severity': rule['severity'],
                    'message': f"Rule '{rule['name']}' triggered: {event.title}"
                }
                alerts.append(alert)
                
                # Store alert in database
                self._store_alert(alert)
        
        return alerts
    
    def _matches_rule(self, event: SystemEvent, rule: Dict) -> bool:
        """Check if an event matches a rule pattern"""
        pattern = rule['pattern']
        
        # Simple pattern matching - can be extended with regex or more complex logic
        event_text = f"{event.title} {event.description} {event.source}"
        
        return pattern.lower() in event_text.lower()
    
    def _store_alert(self, alert: Dict):
        """Store alert in database"""
        with sqlite3.connect(self.db_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts (id, event_id, rule_id, severity, message, acknowledged)
                VALUES (?, ?, ?, ?, ?, FALSE)
            ''', (alert['id'], alert['event_id'], alert['rule_id'], 
                  alert['severity'], alert['message']))
            conn.commit()

class SystemMonitor:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.hostname = platform.node()
        self.running = False
        self.monitors = {}
        self.suricata_log_path = "/var/log/suricata/eve.json"
        
    def start_monitoring(self):
        """Start all monitoring threads"""
        self.running = True
        
        # Start different monitoring threads
        self.monitors['process'] = threading.Thread(target=self._monitor_processes)
        self.monitors['performance'] = threading.Thread(target=self._monitor_performance)
        self.monitors['network'] = threading.Thread(target=self._monitor_network)
        self.monitors['suricata'] = threading.Thread(target=self._monitor_suricata)
        
        for monitor in self.monitors.values():
            monitor.daemon = True
            monitor.start()
    
    def stop_monitoring(self):
        """Stop all monitoring"""
        self.running = False
    
    def _monitor_processes(self):
        """Monitor process events"""
        known_processes = set()
        
        while self.running:
            try:
                current_processes = set()
                for proc in psutil.process_iter(['pid', 'name', 'username']):
                    try:
                        current_processes.add(proc.info['pid'])
                        
                        # New process detected
                        if proc.info['pid'] not in known_processes:
                            event = SystemEvent(
                                id=str(uuid.uuid4()),
                                agent_id=self.agent_id,
                                hostname=self.hostname,
                                timestamp=datetime.now(),
                                event_type=EventType.PROCESS_START,
                                severity=Severity.LOW,
                                title=f"Process started: {proc.info['name']}",
                                description=f"PID: {proc.info['pid']}, User: {proc.info['username']}",
                                source="process_monitor",
                                data={
                                    'pid': proc.info['pid'],
                                    'name': proc.info['name'],
                                    'username': proc.info['username']
                                }
                            )
                            yield event
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Check for ended processes
                for pid in known_processes - current_processes:
                    event = SystemEvent(
                        id=str(uuid.uuid4()),
                        agent_id=self.agent_id,
                        hostname=self.hostname,
                        timestamp=datetime.now(),
                        event_type=EventType.PROCESS_END,
                        severity=Severity.LOW,
                        title=f"Process ended: PID {pid}",
                        description=f"Process with PID {pid} has terminated",
                        source="process_monitor",
                        data={'pid': pid}
                    )
                    yield event
                
                known_processes = current_processes
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error in process monitoring: {e}")
                time.sleep(10)
    
    def _monitor_performance(self):
        """Monitor system performance"""
        while self.running:
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > 80:
                    event = SystemEvent(
                        id=str(uuid.uuid4()),
                        agent_id=self.agent_id,
                        hostname=self.hostname,
                        timestamp=datetime.now(),
                        event_type=EventType.PERFORMANCE_ALERT,
                        severity=Severity.HIGH,
                        title="High CPU Usage",
                        description=f"CPU usage is {cpu_percent}%",
                        source="performance_monitor",
                        data={'cpu_percent': cpu_percent}
                    )
                    yield event
                
                # Memory usage
                memory = psutil.virtual_memory()
                if memory.percent > 85:
                    event = SystemEvent(
                        id=str(uuid.uuid4()),
                        agent_id=self.agent_id,
                        hostname=self.hostname,
                        timestamp=datetime.now(),
                        event_type=EventType.PERFORMANCE_ALERT,
                        severity=Severity.HIGH,
                        title="High Memory Usage",
                        description=f"Memory usage is {memory.percent}%",
                        source="performance_monitor",
                        data={
                            'memory_percent': memory.percent,
                            'available_mb': memory.available / (1024 * 1024)
                        }
                    )
                    yield event
                
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Error in performance monitoring: {e}")
                time.sleep(60)
    
    def _monitor_network(self):
        """Monitor network connections"""
        while self.running:
            try:
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        event = SystemEvent(
                            id=str(uuid.uuid4()),
                            agent_id=self.agent_id,
                            hostname=self.hostname,
                            timestamp=datetime.now(),
                            event_type=EventType.NETWORK_CONNECTION,
                            severity=Severity.LOW,
                            title="Network Connection",
                            description=f"Connection to {conn.raddr.ip}:{conn.raddr.port}",
                            source="network_monitor",
                            data={
                                'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                                'status': conn.status,
                                'pid': conn.pid
                            }
                        )
                        yield event
                
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in network monitoring: {e}")
                time.sleep(120)

    def _monitor_suricata(self):
        """Monitor Suricata EVE JSON log for alerts"""
        import os
        import time
        if not os.path.exists(self.suricata_log_path):
            logger.warning(f"Suricata log not found: {self.suricata_log_path}")
            while self.running:
                time.sleep(60)
            return
        with open(self.suricata_log_path, 'r') as f:
            # Go to the end of the file
            f.seek(0, os.SEEK_END)
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get('event_type') == 'alert':
                        event = SystemEvent(
                            id=str(uuid.uuid4()),
                            agent_id=self.agent_id,
                            hostname=self.hostname,
                            timestamp=datetime.fromtimestamp(entry.get('timestamp', time.time())) if 'timestamp' in entry else datetime.now(),
                            event_type=EventType.SECURITY_ALERT,
                            severity=Severity.HIGH,
                            title=f"Suricata Alert: {entry['alert'].get('signature', 'Unknown')}" if 'alert' in entry else "Suricata Alert",
                            description=entry['alert'].get('signature', '') if 'alert' in entry else json.dumps(entry),
                            source="suricata",
                            data=entry
                        )
                        yield event
                except Exception as e:
                    logger.error(f"Error parsing Suricata log: {e}")

class MonitoringAgent:
    def __init__(self, server_host: str = "localhost", server_port: int = 8080, db_path: str = "monitoring.db"):
        self.agent_id = str(uuid.uuid4())
        self.server_host = server_host
        self.server_port = server_port
        self.monitor = SystemMonitor(self.agent_id)
        self.running = False
        self.db_manager = DatabaseManager(db_path)
    
    def start(self):
        """Start the monitoring agent"""
        self.running = True
        logger.info(f"Starting monitoring agent {self.agent_id}")
        
        # Register with server
        self._register_with_server()
        
        # Start monitoring
        self.monitor.start_monitoring()
        
        # Start event processing loop
        self._process_events()
    
    def stop(self):
        """Stop the monitoring agent"""
        self.running = False
        self.monitor.stop_monitoring()
        logger.info(f"Stopping monitoring agent {self.agent_id}")
    
    def _register_with_server(self):
        """Register this agent with the monitoring server"""
        try:
            registration_data = {
                'agent_id': self.agent_id,
                'hostname': platform.node(),
                'ip_address': socket.gethostbyname(socket.gethostname()),
                'os_info': f"{platform.system()} {platform.release()}",
                'version': "1.0.0"
            }
            # Register directly in the database (local mode)
            registered = self.db_manager.register_agent(
                registration_data['agent_id'],
                registration_data['hostname'],
                registration_data['ip_address'],
                registration_data['os_info'],
                registration_data['version']
            )
            if registered:
                logger.info(f"Registered agent in DB: {registration_data}")
            else:
                logger.error(f"Failed to register agent in DB: {registration_data}")
        except Exception as e:
            logger.error(f"Failed to register with server: {e}")
    
    def _process_events(self):
        """Process events from monitors and send to server"""
        while self.running:
            try:
                # Collect events from all monitors
                for monitor_name, monitor_thread in self.monitor.monitors.items():
                    if hasattr(monitor_thread, 'target'):
                        # In a real implementation, you'd use queues or other IPC
                        # This is a simplified example
                        pass
                
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error processing events: {e}")
                time.sleep(5)

class MonitoringServer:
    def __init__(self, host: str = "localhost", port: int = 8080, db_path: str = "monitoring.db"):
        self.host = host
        self.port = port
        self.db_manager = DatabaseManager(db_path)
        self.rule_engine = RuleEngine(self.db_manager)
        self.running = False
        self.agents = {}
        
        # Add some default rules
        self._add_default_rules()
    
    def _add_default_rules(self):
        """Add some default monitoring rules"""
        default_rules = [
            {
                'name': 'High CPU Usage',
                'description': 'Alert when CPU usage exceeds 80%',
                'pattern': 'High CPU Usage',
                'severity': Severity.HIGH.value
            },
            {
                'name': 'Process Monitoring',
                'description': 'Monitor critical process events',
                'pattern': 'Process started',
                'severity': Severity.MEDIUM.value
            },
            {
                'name': 'Security Alert',
                'description': 'Security-related events',
                'pattern': 'security',
                'severity': Severity.CRITICAL.value
            }
        ]
        # Only add if not already present
        with sqlite3.connect(self.db_manager.db_path) as conn:
            cursor = conn.cursor()
            for rule in default_rules:
                cursor.execute('SELECT COUNT(*) FROM rules WHERE name = ? AND pattern = ?', (rule['name'], rule['pattern']))
                if cursor.fetchone()[0] == 0:
                    self.rule_engine.add_rule(
                        rule['name'],
                        rule['description'],
                        rule['pattern'],
                        rule['severity']
                    )
    
    def start(self):
        """Start the monitoring server"""
        self.running = True
        logger.info(f"Starting monitoring server on {self.host}:{self.port}")
        
        # Start agent status checker
        status_thread = threading.Thread(target=self._check_agent_status)
        status_thread.daemon = True
        status_thread.start()
        
        # In a real implementation, you'd start a TCP/HTTP server here
        # For now, we'll just run a simple loop
        self._run_server()
    
    def stop(self):
        """Stop the monitoring server"""
        self.running = False
        logger.info("Stopping monitoring server")
    
    def _run_server(self):
        """Main server loop"""
        while self.running:
            try:
                # Process incoming events, handle agent communications, etc.
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in server loop: {e}")
                time.sleep(5)
    
    def _check_agent_status(self):
        """Check agent status and mark inactive agents"""
        while self.running:
            try:
                agents = self.db_manager.get_agents()
                for agent in agents:
                    last_seen = datetime.fromisoformat(agent['last_seen'])
                    if datetime.now() - last_seen > timedelta(minutes=5):
                        self.db_manager.update_agent_status(agent['id'], 'inactive')
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error checking agent status: {e}")
                time.sleep(60)
    
    def process_event(self, event: SystemEvent):
        """Process an incoming event"""
        # Store the event
        if self.db_manager.store_event(event):
            logger.info(f"Stored event: {event.title}")
            
            # Evaluate against rules
            alerts = self.rule_engine.evaluate_event(event)
            if alerts:
                logger.warning(f"Generated {len(alerts)} alerts for event: {event.title}")
        else:
            logger.warning(f"Failed to store event: {event.title}")
    
    def get_dashboard_data(self) -> Dict:
        """Get dashboard data for frontend"""
        agents = self.db_manager.get_agents()
        recent_events = self.db_manager.get_events(limit=5)
        # Get recent alerts
        with sqlite3.connect(self.db_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, event_id, rule_id, severity, message, acknowledged, created_at
                FROM alerts
                ORDER BY created_at DESC
                LIMIT 5
            ''')
            columns = [desc[0] for desc in cursor.description]
            recent_alerts = [dict(zip(columns, row)) for row in cursor.fetchall()]
            cursor.execute('''
                SELECT COUNT(*) as total_alerts,
                       SUM(CASE WHEN acknowledged = FALSE THEN 1 ELSE 0 END) as unacknowledged
                FROM alerts
            ''')
            alert_stats = cursor.fetchone()
            # Severity distribution for donut chart
            cursor.execute('''
                SELECT severity, COUNT(*) FROM events GROUP BY severity
            ''')
            severity_counts = {row[0]: row[1] for row in cursor.fetchall()}
            # Event type distribution for bar chart
            cursor.execute('''
                SELECT event_type, COUNT(*) FROM events GROUP BY event_type
            ''')
            event_type_counts = {row[0]: row[1] for row in cursor.fetchall()}
        return {
            'agents': {
                'total': len(agents),
                'active': len([a for a in agents if a['status'] == 'active']),
                'inactive': len([a for a in agents if a['status'] == 'inactive']),
                'list': agents
            },
            'events': {
                'recent': recent_events,
                'total': len(recent_events),
                'severity_counts': severity_counts,
                'event_type_counts': event_type_counts
            },
            'alerts': {
                'total': alert_stats[0] if alert_stats else 0,
                'unacknowledged': alert_stats[1] if alert_stats else 0,
                'recent': recent_alerts
            }
        }

app = Flask(__name__)
app.secret_key = 'change_this_secret_key'
server_instance = None

# Ensure root user exists on startup
def ensure_root_user():
    username = 'Regina'
    password = 'pass1234'
    import hashlib
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    users = server_instance.db_manager.get_users()
    if not any(u['username'] == username for u in users):
        server_instance.db_manager.add_user(username, password_hash, 'admin')

# Authentication helpers
def is_logged_in():
    return 'user_id' in session

def require_login():
    if not is_logged_in():
        return redirect(url_for('dashboard_page'))

def is_admin():
    return session.get('username') and any(u['username'] == session['username'] and u['role'] == 'admin' for u in server_instance.db_manager.get_users())

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_logged_in() or not is_admin():
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    import hashlib
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    users = server_instance.db_manager.get_users()
    user = next((u for u in users if u['username'] == username), None)
    if user and server_instance.db_manager:
        with sqlite3.connect(server_instance.db_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            if row and row[1] == password_hash:
                session['user_id'] = row[0]
                session['username'] = username
                return jsonify({'status': 'ok'})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'status': 'logged out'})

# Protect API endpoints
from functools import wraps
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_logged_in():
            return jsonify({'error': 'Not authenticated'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/register_agent', methods=['POST'])
def register_agent_api():
    data = request.json
    required = ['agent_id', 'hostname', 'ip_address', 'os_info', 'version']
    if not all(k in data for k in required):
        return jsonify({'error': 'Missing fields'}), 400
    ok = server_instance.db_manager.register_agent(
        data['agent_id'], data['hostname'], data['ip_address'], data['os_info'], data['version']
    )
    if ok:
        return jsonify({'status': 'registered'}), 200
    else:
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/submit_event', methods=['POST'])
def submit_event_api():
    data = request.json
    try:
        event = SystemEvent(
            id=data['id'],
            agent_id=data['agent_id'],
            hostname=data['hostname'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            event_type=EventType(data['event_type']),
            severity=Severity(data['severity']),
            title=data['title'],
            description=data['description'],
            source=data['source'],
            data=data['data'],
            hash=data.get('hash', '')
        )
        server_instance.process_event(event)
        return jsonify({'status': 'event received'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/dashboard')
def dashboard_page():
    if not is_logged_in():
        # Show login form (unchanged)
        html = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login - Monitoring Dashboard</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 min-h-screen flex items-center justify-center">
            <div class="bg-white p-8 rounded shadow w-full max-w-md">
                <h1 class="text-2xl font-bold mb-6 text-center">SysMon Login</h1>
                <form id="login-form" class="flex flex-col gap-4">
                    <input type="text" id="username" placeholder="Username" class="border px-3 py-2 rounded" required />
                    <input type="password" id="password" placeholder="Password" class="border px-3 py-2 rounded" required />
                    <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">Login</button>
                </form>
                <div id="login-error" class="text-red-600 mt-2"></div>
            </div>
            <script>
            document.getElementById('login-form').onsubmit = function(e) {
                e.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                }).then(r => r.json()).then(resp => {
                    if (resp.status) {
                        window.location.reload();
                    } else {
                        document.getElementById('login-error').innerText = resp.error || 'Login failed';
                    }
                });
            };
            </script>
        </body>
        </html>
        '''
        return render_template_string(html)
    html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SysMon - Monitoring Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
            * { font-family: 'Inter', sans-serif; }
            .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
            .glass-effect { background: rgba(255, 255, 255, 0.1); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.2); }
            .card-hover { transition: all 0.3s ease; transform: translateY(0); }
            .card-hover:hover { transform: translateY(-4px); box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1); }
            .nav-item { transition: all 0.3s ease; position: relative; overflow: hidden; }
            .nav-item::before { content: ''; position: absolute; left: 0; top: 0; height: 100%; width: 3px; background: linear-gradient(135deg, #667eea, #764ba2); transform: scaleY(0); transition: transform 0.3s ease; }
            .nav-item.active::before, .nav-item:hover::before { transform: scaleY(1); }
            .nav-item.active { background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1)); color: #667eea; }
            .pulse-dot { animation: pulse 2s infinite; }
            @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
            .slide-in { animation: slideIn 0.5s ease-out; }
            @keyframes slideIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
            .metric-card { background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%); border: 1px solid rgba(226, 232, 240, 0.8); }
            .status-online { background: linear-gradient(135deg, #10b981, #059669); color: white; }
            .status-offline { background: linear-gradient(135deg, #ef4444, #dc2626); color: white; }
            .status-warning { background: linear-gradient(135deg, #f59e0b, #d97706); color: white; }
            .search-input { background: rgba(255, 255, 255, 0.9); backdrop-filter: blur(10px); border: 2px solid transparent; transition: all 0.3s ease; }
            .search-input:focus { border-color: #667eea; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1); }
            .btn-primary { background: linear-gradient(135deg, #667eea, #764ba2); transition: all 0.3s ease; }
            .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3); }
            .table-row { transition: all 0.2s ease; }
            .table-row:hover { background: rgba(102, 126, 234, 0.05); transform: scale(1.001); }
            .loading-spinner { display: inline-block; width: 20px; height: 20px; border: 3px solid rgba(255, 255, 255, 0.3); border-radius: 50%; border-top-color: #fff; animation: spin 1s ease-in-out infinite; }
            @keyframes spin { to { transform: rotate(360deg); } }
            .severity-critical { background: linear-gradient(135deg, #ef4444, #dc2626); color: white; }
            .severity-high { background: linear-gradient(135deg, #f97316, #ea580c); color: white; }
            .severity-medium { background: linear-gradient(135deg, #f59e0b, #d97706); color: white; }
            .severity-low { background: linear-gradient(135deg, #10b981, #059669); color: white; }
        </style>
    </head>
    <body class="bg-gray-50 min-h-screen">
        <!-- Sidebar -->
        <nav class="fixed top-0 left-0 bg-white shadow-xl w-72 h-screen flex-shrink-0 z-20 border-r border-gray-200">
            <div class="px-6 py-8 flex flex-col h-full">
                <!-- Logo -->
                <div class="flex items-center mb-12">
                    <div class="w-10 h-10 gradient-bg rounded-xl flex items-center justify-center mr-3">
                        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2z"></path>
                        </svg>
                    </div>
                    <div>
                        <div class="text-2xl font-bold text-gray-800">SysMon</div>
                        <div class="text-sm text-gray-500">Monitoring Dashboard</div>
                    </div>
                </div>
                <!-- Navigation -->
                <div class="flex flex-col gap-2 mb-8">
                    <button id="nav-dashboard" class="nav-item active text-left px-4 py-3 rounded-lg text-base font-medium text-gray-700 hover:bg-gray-100 flex items-center">
                        <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2-2z"></path>
                        </svg>
                        Dashboard
                    </button>
                    <button id="nav-alerts" class="nav-item text-left px-4 py-3 rounded-lg text-base font-medium text-gray-700 hover:bg-gray-100 flex items-center">
                        <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                        </svg>
                        Alerts
                        <span id="alert-badge" class="ml-auto bg-red-500 text-white text-xs px-2 py-1 rounded-full">0</span>
                    </button>
                    <button id="nav-events" class="nav-item text-left px-4 py-3 rounded-lg text-base font-medium text-gray-700 hover:bg-gray-100 flex items-center">
                        <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path>
                        </svg>
                        Events
                    </button>
                    <button id="nav-users" class="nav-item text-left px-4 py-3 rounded-lg text-base font-medium text-gray-700 hover:bg-gray-100 flex items-center">
                        <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"></path>
                        </svg>
                        Users
                    </button>
                </div>
                <!-- Status Indicator -->
                <div class="mb-8 p-4 bg-gray-50 rounded-lg">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-sm font-medium text-gray-700">System Status</span>
                        <div class="flex items-center">
                            <div class="w-2 h-2 bg-green-500 rounded-full pulse-dot mr-2"></div>
                            <span class="text-sm text-green-600">Online</span>
                        </div>
                    </div>
                    <div class="text-xs text-gray-500">Last updated: just now</div>
                </div>
                <!-- Logout -->
                <div class="mt-auto">
                    <button id="nav-logout" class="w-full text-left px-4 py-3 rounded-lg text-base font-medium text-gray-700 hover:bg-red-50 hover:text-red-600 flex items-center transition-colors">
                        <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path>
                        </svg>
                        Logout
                    </button>
                </div>
            </div>
        </nav>
        <!-- Main Content -->
        <main class="ml-72 p-8 min-h-screen">
            <div id="dashboard-root" class="slide-in">
                <div id="dashboard-content"></div>
            </div>
        </main>
        <script>
        // --- JS for dynamic dashboard ---
        // Helper functions for badges
        function getSeverityBadge(severity) {
            const severityMap = {
                4: 'severity-critical',
                3: 'severity-high',
                2: 'severity-medium',
                1: 'severity-low',
                'Critical': 'severity-critical',
                'High': 'severity-high',
                'Medium': 'severity-medium',
                'Low': 'severity-low'
            };
            let sev = severity;
            if (typeof sev === 'number') {
                sev = {1:'Low',2:'Medium',3:'High',4:'Critical'}[sev] || sev;
            }
            return `<span class="px-2 py-1 rounded-full text-xs font-medium ${severityMap[severity] || severityMap[sev] || 'bg-gray-100 text-gray-800'}">${sev}</span>`;
        }
        function getStatusBadge(status) {
            const statusMap = {
                'active': 'status-online',
                'inactive': 'status-offline',
                'warning': 'status-warning',
                'Active': 'status-online',
                'Inactive': 'status-offline',
                'Warning': 'status-warning'
            };
            return `<span class="px-2 py-1 rounded-full text-xs font-medium ${statusMap[status] || 'bg-gray-100 text-gray-800'}">${status}</span>`;
        }
        // --- Dashboard ---
        function renderDashboard() {
            setActiveNav('nav-dashboard');
            // Destroy charts before replacing the DOM
            if (eventTypeChartInstance) {
                eventTypeChartInstance.destroy();
                eventTypeChartInstance = null;
            }
            if (severityChartInstance) {
                severityChartInstance.destroy();
                severityChartInstance = null;
            }
            fetch('/api/dashboard').then(r => r.json()).then(data => {
                document.getElementById('alert-badge').textContent = data.alerts.unacknowledged;
                const root = document.getElementById('dashboard-content');
                root.innerHTML = `
                    <div class="slide-in">
                        <div class="mb-8">
                            <h1 class="text-3xl font-bold text-gray-900 mb-2">System Overview</h1>
                            <p class="text-gray-600">Monitor your infrastructure in real-time</p>
                        </div>
                        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                            <div class="metric-card card-hover p-6 rounded-2xl shadow-sm">
                                <div class="flex items-center justify-between mb-4">
                                    <div class="text-gray-500 text-sm font-medium">Total Agents</div>
                                    <div class="w-12 h-12 gradient-bg rounded-xl flex items-center justify-center">
                                        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg>
                                    </div>
                                </div>
                                <div class="text-3xl font-bold text-gray-900 mb-2">${data.agents.total}</div>
                                <div class="flex items-center text-sm">
                                    <span class="text-green-600 font-medium">${data.agents.active} Active</span>
                                    <span class="text-gray-400 mx-2">•</span>
                                    <span class="text-red-600 font-medium">${data.agents.inactive} Inactive</span>
                                </div>
                            </div>
                            <div class="metric-card card-hover p-6 rounded-2xl shadow-sm">
                                <div class="flex items-center justify-between mb-4">
                                    <div class="text-gray-500 text-sm font-medium">Recent Events</div>
                                    <div class="w-12 h-12 bg-blue-500 rounded-xl flex items-center justify-center">
                                        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path></svg>
                                    </div>
                                </div>
                                <div class="text-3xl font-bold text-gray-900 mb-2">${data.events.total}</div>
                                <div class="text-sm text-gray-600">Last 24 hours</div>
                            </div>
                            <div class="metric-card card-hover p-6 rounded-2xl shadow-sm">
                                <div class="flex items-center justify-between mb-4">
                                    <div class="text-gray-500 text-sm font-medium">Active Alerts</div>
                                    <div class="w-12 h-12 bg-orange-500 rounded-xl flex items-center justify-center">
                                        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path></svg>
                                    </div>
                                </div>
                                <div class="text-3xl font-bold text-gray-900 mb-2">${data.alerts.total}</div>
                                <div class="text-sm text-orange-600 font-medium">${data.alerts.unacknowledged} Unacknowledged</div>
                            </div>
                           
                        </div>
                        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                            <div class="col-span-2 bg-white card-hover p-6 rounded-2xl shadow-sm">
                                <h3 class="text-lg font-semibold text-gray-900 mb-4">Event Types Distribution</h3>
                                <canvas id="eventTypeChart" height="200"></canvas>
                            </div>
                            <div class="bg-white card-hover p-6 rounded-2xl shadow-sm">
                                <h3 class="text-lg font-semibold text-gray-900 mb-4">Severity Distribution</h3>
                                <canvas id="severityDonut" height="200"></canvas>
                            </div>
                        </div>
                        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
                            <div class="bg-white card-hover p-6 rounded-2xl shadow-sm">
                                <div class="flex items-center justify-between mb-4">
                                    <h3 class="text-lg font-semibold text-gray-900">Recent Events</h3>
                                    <button class="text-sm text-blue-600 hover:text-blue-800 font-medium" onclick="renderAllEvents()">View All</button>
                                </div>
                                <div class="space-y-3">
                                    ${data.events.recent.map(event => `
                                        <div class="flex items-center p-3 rounded-lg hover:bg-gray-50 transition-colors">
                                            <div class="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
                                            <div class="flex-1">
                                                <div class="font-medium text-gray-900 text-sm">${event.title}</div>
                                                <div class="text-xs text-gray-500">${event.agent_id} • ${event.timestamp}</div>
                                            </div>
                                            ${getSeverityBadge(event.severity)}
                                        </div>
                                    `).join('')}
                                </div>
                            </div>
                            <div class="bg-white card-hover p-6 rounded-2xl shadow-sm">
                                <div class="flex items-center justify-between mb-4">
                                    <h3 class="text-lg font-semibold text-gray-900">Recent Alerts</h3>
                                    <button class="text-sm text-blue-600 hover:text-blue-800 font-medium" onclick="renderAllAlerts()">View All</button>
                                </div>
                                <div class="space-y-3">
                                    ${data.alerts.recent.map(alert => `
                                        <div class="flex items-center p-3 rounded-lg hover:bg-gray-50 transition-colors">
                                            <div class="w-2 h-2 ${alert.acknowledged ? 'bg-green-500' : 'bg-red-500'} rounded-full mr-3"></div>
                                            <div class="flex-1">
                                                <div class="font-medium text-gray-900 text-sm">${alert.message}</div>
                                                <div class="text-xs text-gray-500">${alert.created_at}</div>
                                            </div>
                                            ${getSeverityBadge(alert.severity)}
                                        </div>
                                    `).join('')}
                                </div>
                            </div>
                        </div>
                        <div class="bg-white card-hover p-6 rounded-2xl shadow-sm">
                            <div class="flex items-center justify-between mb-6">
                                <h3 class="text-lg font-semibold text-gray-900">Agent Status</h3>
                                <div class="flex items-center space-x-4">
                                    <div class="flex items-center">
                                        <div class="w-3 h-3 bg-green-500 rounded-full mr-2"></div>
                                        <span class="text-sm text-gray-600">Active</span>
                                    </div>
                                    <div class="flex items-center">
                                        <div class="w-3 h-3 bg-red-500 rounded-full mr-2"></div>
                                        <span class="text-sm text-gray-600">Inactive</span>
                                    </div>
                                </div>
                            </div>
                            <div class="overflow-x-auto">
                                <table class="min-w-full">
                                    <thead class="bg-gray-50">
                                        <tr>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Agent</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Hostname</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Address</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Seen</th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white divide-y divide-gray-200">
                                        ${data.agents.list.map(agent => `
                                            <tr class="table-row">
                                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${agent.id}</td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${agent.hostname}</td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${agent.ip_address}</td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${getStatusBadge(agent.status)}</td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${agent.last_seen}</td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                `;
                // Render charts after DOM update
                setTimeout(() => {
                    renderEventTypeChart(data.events.event_type_counts);
                    renderSeverityChart(data.events.severity_counts);
                }, 100);
            });
        }
        // Add these variables at the top of the <script> (before chart functions)
        let eventTypeChartInstance = null;
        let severityChartInstance = null;
        function renderEventTypeChart(data) {
            const ctx = document.getElementById('eventTypeChart');
            if (!ctx) return;
            // Destroy previous chart if exists
            if (eventTypeChartInstance) {
                eventTypeChartInstance.destroy();
            }
            eventTypeChartInstance = new Chart(ctx.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: Object.keys(data),
                    datasets: [{
                        label: 'Event Count',
                        data: Object.values(data),
                        backgroundColor: 'rgba(102, 126, 234, 0.8)',
                        borderColor: 'rgba(102, 126, 234, 1)',
                        borderWidth: 1,
                        borderRadius: 6,
                        borderSkipped: false,
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { beginAtZero: true, grid: { color: 'rgba(0, 0, 0, 0.1)' } },
                        x: { grid: { display: false } }
                    }
                }
            });
        }
        function renderSeverityChart(data) {
            const ctx = document.getElementById('severityDonut');
            if (!ctx) return;
            // Destroy previous chart if exists
            if (severityChartInstance) {
                severityChartInstance.destroy();
            }
            const sevMap = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'};
            const labels = [1,2,3,4].map(k => sevMap[k]);
            const values = [1,2,3,4].map(k => data[k] || 0);
            severityChartInstance = new Chart(ctx.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: values,
                        backgroundColor: ['#10b981', '#f59e0b', '#f97316', '#ef4444'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { padding: 20, usePointStyle: true }
                        }
                    }
                }
            });
        }
        // --- Alerts ---
        function renderAllAlerts() {
            setActiveNav('nav-alerts');
            let searchTimeout;
            fetch('/api/all_alerts').then(r => r.json()).then(alerts => render(alerts, ''));
            function render(alerts, query = '') {
                const root = document.getElementById('dashboard-content');
                root.innerHTML = `
                    <div class="slide-in">
                        <div class="mb-8">
                            <h1 class="text-3xl font-bold text-gray-900 mb-2">Alert Management</h1>
                            <p class="text-gray-600">Monitor and manage system alerts</p>
                        </div>
                        <div class="bg-white card-hover p-6 rounded-2xl shadow-sm mb-6">
                            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                                <div class="relative flex-1 max-w-md">
                                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                        <svg class="h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                                    </div>
                                    <input id="alerts-search" type="text" placeholder="Search alerts..." class="search-input pl-10 pr-4 py-2 border-0 rounded-lg w-full focus:outline-none focus:ring-0" value="${query}">
                                </div>
                                <div class="flex items-center space-x-4">
                                    <span class="text-sm text-gray-600">Total: ${alerts.length}</span>
                                    <span class="text-sm text-red-600">Unacknowledged: ${alerts.filter(a => !a.acknowledged).length}</span>
                                </div>
                            </div>
                        </div>
                        <div class="bg-white card-hover rounded-2xl shadow-sm overflow-hidden">
                            <div class="overflow-x-auto">
                                <table class="min-w-full">
                                    <thead class="bg-gray-50">
                                        <tr>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Message</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white divide-y divide-gray-200">
                                        ${alerts.map(alert => `
                                            <tr class="table-row">
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${alert.created_at}</td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${getSeverityBadge(alert.severity)}</td>
                                                <td class="px-6 py-4 text-sm text-gray-900 max-w-md">${alert.message}</td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                                    ${alert.acknowledged ? '<span class="px-2 py-1 bg-green-100 text-green-800 rounded-full text-xs font-medium">Acknowledged</span>' : '<span class="px-2 py-1 bg-red-100 text-red-800 rounded-full text-xs font-medium">Pending</span>'}
                                                </td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                `;
                // Search functionality
                const searchInput = document.getElementById('alerts-search');
                searchInput.oninput = function() {
                    clearTimeout(searchTimeout);
                    const val = this.value.toLowerCase();
                    searchTimeout = setTimeout(() => {
                        fetch(`/api/all_alerts?q=${encodeURIComponent(val)}`).then(r => r.json()).then(alerts2 => render(alerts2, val));
                    }, 300);
                };
            }
        }
        // --- Events ---
        function renderAllEvents() {
            setActiveNav('nav-events');
            let searchTimeout;
            fetch('/api/all_events').then(r => r.json()).then(events => render(events, ''));
            function render(events, query = '') {
                const root = document.getElementById('dashboard-content');
                root.innerHTML = `
                    <div class="slide-in">
                        <div class="mb-8">
                            <h1 class="text-3xl font-bold text-gray-900 mb-2">Event Log</h1>
                            <p class="text-gray-600">View and search system events</p>
                        </div>
                        <div class="bg-white card-hover p-6 rounded-2xl shadow-sm mb-6">
                            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                                <div class="relative flex-1 max-w-md">
                                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                        <svg class="h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                                    </div>
                                    <input id="events-search" type="text" placeholder="Search events..." class="search-input pl-10 pr-4 py-2 border-0 rounded-lg w-full focus:outline-none focus:ring-0" value="${query}">
                                </div>
                                <div class="flex items-center space-x-4">
                                    <span class="text-sm text-gray-600">Total: ${events.length}</span>
                                </div>
                            </div>
                        </div>
                        <div class="bg-white card-hover rounded-2xl shadow-sm overflow-hidden">
                            <div class="overflow-x-auto">
                                <table class="min-w-full">
                                    <thead class="bg-gray-50">
                                        <tr>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Agent</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Title</th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white divide-y divide-gray-200">
                                        ${events.map(event => `
                                            <tr class="table-row">
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${event.timestamp}</td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${event.agent_id}</td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900"><span class="px-2 py-1 bg-blue-100 text-blue-800 rounded-full text-xs font-medium">${event.event_type}</span></td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${getSeverityBadge(event.severity)}</td>
                                                <td class="px-6 py-4 text-sm text-gray-900">${event.title}</td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                `;
                // Search functionality
                const searchInput = document.getElementById('events-search');
                searchInput.oninput = function() {
                    clearTimeout(searchTimeout);
                    const val = this.value.toLowerCase();
                    searchTimeout = setTimeout(() => {
                        fetch(`/api/all_events?q=${encodeURIComponent(val)}`).then(r => r.json()).then(events2 => render(events2, val));
                    }, 300);
                };
            }
        }
        // --- Users (admin only) ---
        function renderUsers() {
            setActiveNav('nav-users');
            fetch('/api/users').then(r => r.json()).then(users => render(users));
            function render(users) {
                const root = document.getElementById('dashboard-content');
                root.innerHTML = `
                    <div class="slide-in">
                        <div class="mb-8">
                            <h1 class="text-3xl font-bold text-gray-900 mb-2">User Management</h1>
                            <p class="text-gray-600">Manage system users and permissions</p>
                        </div>
                        <div class="bg-white card-hover p-6 rounded-2xl shadow-sm mb-6">
                            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                                <div class="flex items-center space-x-4">
                                    <span class="text-sm text-gray-600">Total Users: ${users.length}</span>
                                    <span class="text-sm text-blue-600">Admins: ${users.filter(u => u.role === 'admin').length}</span>
                                </div>
                                <button id="show-add-user" class="btn-primary text-white px-6 py-2 rounded-lg shadow-lg hover:shadow-xl">
                                    <svg class="w-5 h-5 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path></svg>
                                    Add User
                                </button>
                            </div>
                        </div>
                        <div id="add-user-form" class="hidden mb-6 bg-white card-hover p-6 rounded-2xl shadow-sm">
                            <h3 class="text-lg font-semibold text-gray-900 mb-4">Add New User</h3>
                            <form id="user-form" class="grid grid-cols-1 md:grid-cols-4 gap-4">
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Username</label>
                                    <input type="text" id="username" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Password</label>
                                    <input type="password" id="password" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Role</label>
                                    <select id="role" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                                        <option value="user">User</option>
                                        <option value="admin">Admin</option>
                                    </select>
                                </div>
                                <div class="flex items-end space-x-2">
                                    <button type="submit" class="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition-colors">Add User</button>
                                    <button type="button" id="cancel-add-user" class="text-gray-500 hover:text-red-600 px-4 py-2 transition-colors">Cancel</button>
                                </div>
                            </form>
                            <div id="add-user-error" class="text-red-600 mt-2 text-sm"></div>
                        </div>
                        <div class="bg-white card-hover rounded-2xl shadow-sm overflow-hidden">
                            <div class="overflow-x-auto">
                                <table class="min-w-full">
                                    <thead class="bg-gray-50">
                                        <tr>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Username</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white divide-y divide-gray-200">
                                        ${users.map(user => `
                                            <tr class="table-row">
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 font-medium">${user.username}</td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900"><span class="px-2 py-1 ${user.role === 'admin' ? 'bg-purple-100 text-purple-800' : 'bg-gray-100 text-gray-800'} rounded-full text-xs font-medium">${user.role}</span></td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${user.created_at}</td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900"><button class="delete-user text-red-600 hover:text-red-800 font-medium transition-colors" data-id="${user.id}">Delete</button></td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                `;
                document.getElementById('show-add-user').onclick = () => {
                    document.getElementById('add-user-form').classList.remove('hidden');
                };
                document.getElementById('cancel-add-user').onclick = () => {
                    document.getElementById('add-user-form').classList.add('hidden');
                    document.getElementById('add-user-error').textContent = '';
                };
                document.getElementById('user-form').onsubmit = (e) => {
                    e.preventDefault();
                    const username = document.getElementById('username').value;
                    const password = document.getElementById('password').value;
                    const role = document.getElementById('role').value;
                    fetch('/api/users', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password, role })
                    }).then(r => r.json()).then(resp => {
                        if (resp.status) {
                            renderUsers();
                        } else {
                            document.getElementById('add-user-error').textContent = resp.error || 'Failed to add user';
                        }
                    });
                };
                document.querySelectorAll('.delete-user').forEach(btn => {
                    btn.onclick = () => {
                        if (confirm('Are you sure you want to delete this user?')) {
                            fetch(`/api/users/${btn.dataset.id}`, { method: 'DELETE' })
                                .then(r => r.json()).then(resp => {
                                    renderUsers();
                                });
                        }
                    };
                });
            }
        }
        // --- Navigation ---
        function setActiveNav(activeId) {
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active');
            });
            document.getElementById(activeId).classList.add('active');
        }
        document.getElementById('nav-dashboard').onclick = renderDashboard;
        document.getElementById('nav-alerts').onclick = renderAllAlerts;
        document.getElementById('nav-events').onclick = renderAllEvents;
        document.getElementById('nav-users').onclick = renderUsers;
        document.getElementById('nav-logout').onclick = () => {
            fetch('/logout', { method: 'POST' }).then(r => r.json()).then(resp => {
                if (resp.status === 'logged out') {
                    window.location.reload();
                }
            });
        };
        // Default view
        renderDashboard();
        // Auto-refresh dashboard every 30 seconds
        setInterval(() => {
            if (document.getElementById('nav-dashboard').classList.contains('active')) {
                renderDashboard();
            }
        }, 30000);
        </script>
    </body>
    </html>
    '''
    return render_template_string(html)

@app.route('/api/dashboard')
@login_required
def api_dashboard():
    return jsonify(server_instance.get_dashboard_data())

@app.route('/api/all_alerts')
@login_required
def api_all_alerts():
    q = request.args.get('q', '').strip().lower()
    with sqlite3.connect(server_instance.db_manager.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, event_id, rule_id, severity, message, acknowledged, created_at
            FROM alerts
            ORDER BY created_at DESC
            LIMIT 100
        ''')
        columns = [desc[0] for desc in cursor.description]
        alerts = [dict(zip(columns, row)) for row in cursor.fetchall()]
    if q:
        alerts = [a for a in alerts if q in str(a['message']).lower() or q in str(a['severity']).lower() or q in str(a['created_at']).lower()]
    return jsonify(alerts)

@app.route('/api/all_events')
@login_required
def api_all_events():
    q = request.args.get('q', '').strip().lower()
    events = server_instance.db_manager.get_events(limit=100)
    if q:
        events = [e for e in events if q in str(e['title']).lower() or q in str(e['event_type']).lower() or q in str(e['agent_id']).lower() or q in str(e['description']).lower()]
    return jsonify(events)

@app.route('/api/users', methods=['GET'])
@admin_required
def api_list_users():
    return jsonify(server_instance.db_manager.get_users())

@app.route('/api/users', methods=['POST'])
@admin_required
def api_add_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    import hashlib
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    ok = server_instance.db_manager.add_user(username, password_hash, role)
    if ok:
        return jsonify({'status': 'user added'}), 200
    else:
        return jsonify({'error': 'Failed to add user'}), 500

@app.route('/api/users/<user_id>', methods=['DELETE'])
@admin_required
def api_delete_user(user_id):
    # Prevent deletion of root user
    users = server_instance.db_manager.get_users()
    user = next((u for u in users if u['id'] == user_id), None)
    if user and user['username'] == 'Regina':
        return jsonify({'error': 'Cannot delete root user'}), 403
    ok = server_instance.db_manager.delete_user(user_id)
    if ok:
        return jsonify({'status': 'user deleted'})
    else:
        return jsonify({'error': 'Failed to delete user'}), 500

# Example usage and testing
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'flask':
        server_instance = MonitoringServer()
        ensure_root_user()
        app.run(host='0.0.0.0', port=8080, debug=True)
    else:
        # Create a simple test
        def test_system():
            # Initialize server
            server = MonitoringServer(db_path="test_monitoring.db")
            
            # Create a test event
            test_event = SystemEvent(
                id=str(uuid.uuid4()),
                agent_id="test-agent-1",
                hostname="test-host",
                timestamp=datetime.now(),
                event_type=EventType.PROCESS_START,
                severity=Severity.MEDIUM,
                title="Test Process Started",
                description="This is a test process event",
                source="test_monitor",
                data={'pid': 1234, 'name': 'test_process'}
            )
            
            # Process the event
            server.process_event(test_event)
            
            # Get dashboard data
            dashboard = server.get_dashboard_data()
            print("Dashboard Data:", json.dumps(dashboard, indent=2, default=str))
            
            # Test database queries
            events = server.db_manager.get_events(limit=10)
            print(f"Found {len(events)} events")
            
            for event in events:
                print(f"Event: {event['title']} - {event['timestamp']}")
        
        # Run test
        test_system()
