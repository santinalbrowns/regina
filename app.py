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
        # Show login form
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
        <title>Monitoring Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body class="bg-gray-100 min-h-screen">
        <div>
            <nav class="fixed top-0 left-0 bg-white shadow w-64 h-screen flex-shrink-0 z-10">
                <div class="px-6 py-8 flex flex-col h-full">
                    <div class="text-2xl font-bold text-blue-700 mb-10">SysMon</div>
                    <div class="flex flex-col gap-2">
                        <button id="nav-dashboard" class="text-left px-4 py-2 rounded text-lg font-semibold text-gray-700 hover:bg-blue-100">Dashboard</button>
                        <button id="nav-alerts" class="text-left px-4 py-2 rounded text-lg font-semibold text-gray-700 hover:bg-blue-100">Alerts</button>
                        <button id="nav-events" class="text-left px-4 py-2 rounded text-lg font-semibold text-gray-700 hover:bg-blue-100">Events</button>
                        <button id="nav-users" class="text-left px-4 py-2 rounded text-lg font-semibold text-gray-700 hover:bg-blue-100">Users</button>
                    </div>
                    <div class="mt-auto">
                        <button id="nav-logout" class="w-full text-left px-4 py-2 rounded text-lg font-semibold text-gray-700 hover:bg-blue-100">Logout</button>
                    </div>
                </div>
            </nav>
            <main class="ml-0 md:ml-64 p-8">
                <div id="dashboard-root">
                    <div id="dashboard-content"></div>
                </div>
            </main>
        </div>
        <script>
        function renderDashboard() {
            fetch('/api/dashboard').then(r => r.json()).then(data => {
                const root = document.getElementById('dashboard-content');
                root.innerHTML = `
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                        <div class="bg-white p-6 rounded shadow">
                            <div class="text-gray-500">Agents</div>
                            <div class="text-2xl font-bold">${data.agents.total}</div>
                            <div class="text-green-600">Active: ${data.agents.active}</div>
                            <div class="text-red-600">Inactive: ${data.agents.inactive}</div>
                        </div>
                        <div class="bg-white p-6 rounded shadow">
                            <div class="text-gray-500">Events (recent)</div>
                            <div class="text-2xl font-bold">${data.events.total}</div>
                        </div>
                        <div class="bg-white p-6 rounded shadow">
                            <div class="text-gray-500">Alerts</div>
                            <div class="text-2xl font-bold">${data.alerts.total}</div>
                            <div class="text-yellow-600">Unacknowledged: ${data.alerts.unacknowledged}</div>
                        </div>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                        <div class="col-span-2 bg-white p-6 rounded shadow">
                            <h2 class="text-lg font-semibold mb-2">Event Types</h2>
                            <canvas id="eventTypeChart" height="180"></canvas>
                        </div>
                        <div class="bg-white p-6 rounded shadow">
                            <h2 class="text-lg font-semibold mb-2">Severity Distribution</h2>
                            <canvas id="severityDonut" width="120" height="120"></canvas>
                        </div>
                    </div>
                    <h2 class="text-xl font-semibold mb-2">Recent Events</h2>
                    <div class="overflow-x-auto mb-8">
                    <table class="min-w-full bg-white rounded shadow">
                        <thead>
                            <tr>
                                <th class="px-4 py-2">Time</th>
                                <th class="px-4 py-2">Agent</th>
                                <th class="px-4 py-2">Type</th>
                                <th class="px-4 py-2">Severity</th>
                                <th class="px-4 py-2">Title</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.events.recent.map(ev => `
                            <tr>
                                <td class="border px-4 py-2 text-xs">${ev.timestamp}</td>
                                <td class="border px-4 py-2 text-xs">${ev.agent_id}</td>
                                <td class="border px-4 py-2 text-xs">${ev.event_type}</td>
                                <td class="border px-4 py-2 text-xs">${ev.severity}</td>
                                <td class="border px-4 py-2 text-xs">${ev.title}</td>
                            </tr>
                            `).join('')}
                        </tbody>
                    </table>
                    </div>
                    <h2 class="text-xl font-semibold mb-2">Recent Alerts</h2>
                    <div class="overflow-x-auto mb-8">
                    <table class="min-w-full bg-white rounded shadow">
                        <thead>
                            <tr>
                                <th class="px-4 py-2">Time</th>
                                <th class="px-4 py-2">Severity</th>
                                <th class="px-4 py-2">Message</th>
                                <th class="px-4 py-2">Acknowledged</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.alerts.recent.map(alert => `
                            <tr>
                                <td class="border px-4 py-2 text-xs">${alert.created_at}</td>
                                <td class="border px-4 py-2 text-xs">${alert.severity}</td>
                                <td class="border px-4 py-2 text-xs">${alert.message}</td>
                                <td class="border px-4 py-2 text-xs">${alert.acknowledged ? 'Yes' : 'No'}</td>
                            </tr>
                            `).join('')}
                        </tbody>
                    </table>
                    </div>
                    <h2 class="text-xl font-semibold mt-8 mb-2">Agents</h2>
                    <div class="overflow-x-auto">
                    <table class="min-w-full bg-white rounded shadow">
                        <thead>
                            <tr>
                                <th class="px-4 py-2">Agent ID</th>
                                <th class="px-4 py-2">Hostname</th>
                                <th class="px-4 py-2">IP</th>
                                <th class="px-4 py-2">Status</th>
                                <th class="px-4 py-2">Last Seen</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.agents.list.map(agent => `
                            <tr>
                                <td class="border px-4 py-2 text-xs">${agent.id}</td>
                                <td class="border px-4 py-2 text-xs">${agent.hostname}</td>
                                <td class="border px-4 py-2 text-xs">${agent.ip_address}</td>
                                <td class="border px-4 py-2 text-xs">${agent.status}</td>
                                <td class="border px-4 py-2 text-xs">${agent.last_seen}</td>
                            </tr>
                            `).join('')}
                        </tbody>
                    </table>
                    </div>
                `;
                // Render Event Type Bar Chart
                const typeLabels = Object.keys(data.events.event_type_counts);
                const typeData = Object.values(data.events.event_type_counts);
                new Chart(document.getElementById('eventTypeChart').getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: typeLabels,
                        datasets: [{
                            label: 'Event Count',
                            data: typeData,
                            backgroundColor: '#2563eb',
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: { legend: { display: false } }
                    }
                });
                // Render Severity Donut Chart
                const sevMap = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'};
                const sevLabels = [1,2,3,4].map(k => sevMap[k]);
                const sevData = [1,2,3,4].map(k => data.events.severity_counts[k] || 0);
                new Chart(document.getElementById('severityDonut').getContext('2d'), {
                    type: 'doughnut',
                    data: {
                        labels: sevLabels,
                        datasets: [{
                            data: sevData,
                            backgroundColor: ['#22c55e','#facc15','#f97316','#ef4444'],
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: { legend: { position: 'bottom' } }
                    }
                });
            });
        }

function renderAllAlerts() {
    let searchTimeout;
    const render = (alerts, q) => {
        const root = document.getElementById('dashboard-content');
        root.innerHTML = `
            <h2 class="text-2xl font-semibold mb-4">Alerts</h2>
            <input id="alerts-search" type="text" placeholder="Search alerts..." class="mb-4 px-3 py-2 border rounded w-full max-w-md" value="${q||''}" />
            <div class="overflow-x-auto">
            <table class="min-w-full bg-white rounded shadow">
                <thead>
                    <tr>
                        <th class="px-4 py-2">Time</th>
                        <th class="px-4 py-2">Severity</th>
                        <th class="px-4 py-2">Message</th>
                        <th class="px-4 py-2">Acknowledged</th>
                    </tr>
                </thead>
                <tbody>
                    ${alerts.map(alert => `
                    <tr>
                        <td class="border px-4 py-2 text-xs">${alert.created_at}</td>
                        <td class="border px-4 py-2 text-xs">${alert.severity}</td>
                        <td class="border px-4 py-2 text-xs">${alert.message}</td>
                        <td class="border px-4 py-2 text-xs">${alert.acknowledged ? 'Yes' : 'No'}</td>
                    </tr>
                    `).join('')}
                </tbody>
            </table>
            </div>
        `;
        document.getElementById('alerts-search').oninput = function() {
            clearTimeout(searchTimeout);
            const val = this.value;
            searchTimeout = setTimeout(() => {
                fetch(`/api/all_alerts?q=${encodeURIComponent(val)}`).then(r => r.json()).then(alerts2 => render(alerts2, val));
            }, 300);
        };
    };
    fetch('/api/all_alerts').then(r => r.json()).then(alerts => render(alerts, ''));
}

function renderAllEvents() {
    let searchTimeout;
    const render = (events, q) => {
        const root = document.getElementById('dashboard-content');
        root.innerHTML = `
            <h2 class="text-2xl font-semibold mb-4">Events</h2>
            <input id="events-search" type="text" placeholder="Search events..." class="mb-4 px-3 py-2 border rounded w-full max-w-md" value="${q||''}" />
            <div class="overflow-x-auto">
            <table class="min-w-full bg-white rounded shadow">
                <thead>
                    <tr>
                        <th class="px-4 py-2">Time</th>
                        <th class="px-4 py-2">Agent</th>
                        <th class="px-4 py-2">Type</th>
                        <th class="px-4 py-2">Severity</th>
                        <th class="px-4 py-2">Title</th>
                    </tr>
                </thead>
                <tbody>
                    ${events.map(ev => `
                    <tr>
                        <td class="border px-4 py-2 text-xs">${ev.timestamp}</td>
                        <td class="border px-4 py-2 text-xs">${ev.agent_id}</td>
                        <td class="border px-4 py-2 text-xs">${ev.event_type}</td>
                        <td class="border px-4 py-2 text-xs">${ev.severity}</td>
                        <td class="border px-4 py-2 text-xs">${ev.title}</td>
                    </tr>
                    `).join('')}
                </tbody>
            </table>
            </div>
        `;
        document.getElementById('events-search').oninput = function() {
            clearTimeout(searchTimeout);
            const val = this.value;
            searchTimeout = setTimeout(() => {
                fetch(`/api/all_events?q=${encodeURIComponent(val)}`).then(r => r.json()).then(events2 => render(events2, val));
            }, 300);
        };
    };
    fetch('/api/all_events').then(r => r.json()).then(events => render(events, ''));
}
        function renderUsers() {
            fetch('/api/users').then(r => r.json()).then(users => {
                const root = document.getElementById('dashboard-content');
                root.innerHTML = `
                    <div class="flex justify-between items-center mb-6">
                        <h2 class="text-2xl font-semibold">User Management</h2>
                        <button id="show-add-user" class="bg-blue-600 text-white px-4 py-2 rounded shadow hover:bg-blue-700">Add User</button>
                    </div>
                    <div id="add-user-form" class="hidden mb-6 bg-white p-6 rounded shadow">
                        <h3 class="text-lg font-bold mb-2">Add New User</h3>
                        <form id="user-form" class="flex flex-col md:flex-row gap-4 items-center">
                            <input type="text" id="username" placeholder="Username" class="border px-3 py-2 rounded w-48" required />
                            <input type="password" id="password" placeholder="Password" class="border px-3 py-2 rounded w-48" required />
                            <select id="role" class="border px-3 py-2 rounded w-32">
                                <option value="user">User</option>
                                <option value="admin">Admin</option>
                            </select>
                            <button type="submit" class="bg-green-600 text-white px-4 py-2 rounded hover:bg-green-700">Add</button>
                            <button type="button" id="cancel-add-user" class="ml-2 text-gray-500 hover:text-red-600">Cancel</button>
                        </form>
                        <div id="add-user-error" class="text-red-600 mt-2"></div>
                    </div>
                    <div class="overflow-x-auto">
                    <table class="min-w-full bg-white rounded shadow">
                        <thead>
                            <tr>
                                <th class="px-4 py-2">Username</th>
                                <th class="px-4 py-2">Role</th>
                                <th class="px-4 py-2">Created</th>
                                <th class="px-4 py-2">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${users.map(user => `
                            <tr>
                                <td class="border px-4 py-2 text-xs">${user.username}</td>
                                <td class="border px-4 py-2 text-xs">${user.role}</td>
                                <td class="border px-4 py-2 text-xs">${user.created_at}</td>
                                <td class="border px-4 py-2 text-xs">
                                    <button class="delete-user bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700" data-id="${user.id}">Delete</button>
                                </td>
                            </tr>
                            `).join('')}
                        </tbody>
                    </table>
                    </div>
                `;
                // Add user form logic
                document.getElementById('show-add-user').onclick = () => {
                    document.getElementById('add-user-form').classList.remove('hidden');
                };
                document.getElementById('cancel-add-user').onclick = () => {
                    document.getElementById('add-user-form').classList.add('hidden');
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
                            document.getElementById('add-user-error').innerText = resp.error || 'Failed to add user';
                        }
                    });
                };
                // Delete user logic
                document.querySelectorAll('.delete-user').forEach(btn => {
                    btn.onclick = () => {
                        if (confirm('Delete this user?')) {
                            fetch(`/api/users/${btn.dataset.id}`, { method: 'DELETE' })
                                .then(r => r.json()).then(resp => {
                                    renderUsers();
                                });
                        }
                    };
                });
            });
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
