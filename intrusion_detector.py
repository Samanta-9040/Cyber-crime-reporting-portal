"""
Intrusion Detection Alert System Module
Monitors and alerts on suspicious system activities
"""

import time
from typing import Dict, List, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
from enum import Enum

class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = 1
    WARNING = 2
    CRITICAL = 3

class IntrusionDetectionSystem:
    """Monitors system for suspicious activities and intrusion attempts"""
    
    # Threshold configurations
    THRESHOLDS = {
        'failed_login_attempts': 5,
        'port_scan_threshold': 20,
        'file_access_threshold': 50,
        'privilege_escalation_threshold': 3,
        'unusual_process_threshold': 10,
        'suspicious_outbound_threshold': 100  # MB
    }
    
    def __init__(self):
        self.alerts = []
        self.event_log = []
        self.suspicious_ips = set()
        self.baseline_processes = set()
        self.time_window = 300  # 5 minutes in seconds
    
    def log_event(self, event: Dict) -> None:
        """
        Log a system event for analysis
        
        Args:
            event: Dictionary with event details
                - type: Event type (login, file_access, network, process, etc.)
                - timestamp: Unix timestamp
                - source_ip: Source IP (for network events)
                - user: User involved
                - details: Additional event details
        """
        if 'timestamp' not in event:
            event['timestamp'] = time.time()
        
        self.event_log.append(event)
    
    def analyze_events(self) -> Dict:
        """
        Analyze logged events for intrusions
        
        Returns:
            Dictionary with detection results
        """
        current_time = time.time()
        window_start = current_time - self.time_window
        
        # Filter recent events
        recent_events = [
            e for e in self.event_log
            if e.get('timestamp', current_time) >= window_start
        ]
        
        if not recent_events:
            return {
                'status': 'OK',
                'timestamp': datetime.now().isoformat(),
                'alerts': [],
                'event_count': 0
            }
        
        # Analyze for various intrusion types
        self._detect_brute_force_attacks(recent_events)
        self._detect_privilege_escalation(recent_events)
        self._detect_suspicious_network_activity(recent_events)
        self._detect_malware_indicators(recent_events)
        self._detect_data_theft_attempts(recent_events)
        self._detect_unauthorized_access(recent_events)
        
        # Calculate threat level
        threat_level = self._calculate_threat_level()
        
        return {
            'status': 'ANALYZED',
            'timestamp': datetime.now().isoformat(),
            'time_window_seconds': self.time_window,
            'events_analyzed': len(recent_events),
            'alerts_triggered': len(self.alerts),
            'threat_level': threat_level,
            'alerts': self.alerts,
            'suspicious_ips': list(self.suspicious_ips)
        }
    
    def _detect_brute_force_attacks(self, events: List[Dict]) -> None:
        """Detect brute force login attempts"""
        failed_logins = defaultdict(list)
        
        for event in events:
            if event.get('type') == 'login' and event.get('status') == 'failed':
                source = event.get('source_ip', event.get('user', 'unknown'))
                failed_logins[source].append(event)
        
        for source, attempts in failed_logins.items():
            if len(attempts) >= self.THRESHOLDS['failed_login_attempts']:
                self.alerts.append({
                    'type': 'BRUTE_FORCE_ATTACK',
                    'severity': AlertSeverity.CRITICAL.name,
                    'timestamp': datetime.now().isoformat(),
                    'description': f'Brute force attack detected: {len(attempts)} failed login attempts from {source}',
                    'source': source,
                    'details': {
                        'failed_attempts': len(attempts),
                        'threshold': self.THRESHOLDS['failed_login_attempts'],
                        'target_users': list(set(e.get('user', 'unknown') for e in attempts))
                    }
                })
                self.suspicious_ips.add(source)
    
    def _detect_privilege_escalation(self, events: List[Dict]) -> None:
        """Detect unauthorized privilege escalation attempts"""
        priv_events = defaultdict(list)
        
        for event in events:
            if event.get('type') == 'privilege_change':
                user = event.get('user', 'unknown')
                priv_events[user].append(event)
        
        for user, events_list in priv_events.items():
            if len(events_list) >= self.THRESHOLDS['privilege_escalation_threshold']:
                self.alerts.append({
                    'type': 'PRIVILEGE_ESCALATION',
                    'severity': AlertSeverity.CRITICAL.name,
                    'timestamp': datetime.now().isoformat(),
                    'description': f'Multiple privilege escalation attempts by user: {user}',
                    'user': user,
                    'details': {
                        'attempt_count': len(events_list),
                        'threshold': self.THRESHOLDS['privilege_escalation_threshold']
                    }
                })
    
    def _detect_suspicious_network_activity(self, events: List[Dict]) -> None:
        """Detect suspicious network patterns"""
        network_events = [e for e in events if e.get('type') == 'network']
        
        source_ips = defaultdict(list)
        for event in network_events:
            src = event.get('source_ip', 'unknown')
            source_ips[src].append(event)
        
        for src_ip, activity in source_ips.items():
            # Check for port scanning
            ports = set(e.get('port') for e in activity if 'port' in e)
            if len(ports) > self.THRESHOLDS['port_scan_threshold']:
                self.alerts.append({
                    'type': 'PORT_SCANNING',
                    'severity': AlertSeverity.WARNING.name,
                    'timestamp': datetime.now().isoformat(),
                    'description': f'Port scanning detected from {src_ip}',
                    'source_ip': src_ip,
                    'details': {
                        'ports_scanned': len(ports),
                        'threshold': self.THRESHOLDS['port_scan_threshold']
                    }
                })
                self.suspicious_ips.add(src_ip)
            
            # Check for unusual outbound traffic
            total_data = sum(e.get('bytes', 0) for e in activity)
            if total_data > self.THRESHOLDS['suspicious_outbound_threshold'] * 1024 * 1024:
                self.alerts.append({
                    'type': 'SUSPICIOUS_OUTBOUND_TRAFFIC',
                    'severity': AlertSeverity.WARNING.name,
                    'timestamp': datetime.now().isoformat(),
                    'description': f'Unusual amount of outbound traffic from {src_ip}',
                    'source_ip': src_ip,
                    'details': {
                        'data_transferred_mb': round(total_data / (1024 * 1024), 2),
                        'threshold_mb': self.THRESHOLDS['suspicious_outbound_threshold']
                    }
                })
    
    def _detect_malware_indicators(self, events: List[Dict]) -> None:
        """Detect malware indicators"""
        process_events = defaultdict(list)
        
        for event in events:
            if event.get('type') == 'process_execution':
                proc_name = event.get('process_name', 'unknown')
                process_events[proc_name].append(event)
        
        # Check for suspicious process behavior
        suspicious_processes = [
            'cmd.exe', 'powershell.exe', 'psexec', 'mimikatz',
            'wmi.exe', 'schtasks.exe', 'reg.exe', 'whoami.exe'
        ]
        
        for event in events:
            if event.get('type') == 'process_execution':
                proc_name = event.get('process_name', '').lower()
                
                for suspicious in suspicious_processes:
                    if suspicious.lower() in proc_name:
                        self.alerts.append({
                            'type': 'MALWARE_INDICATOR',
                            'severity': AlertSeverity.WARNING.name,
                            'timestamp': datetime.now().isoformat(),
                            'description': f'Suspicious process detected: {proc_name}',
                            'process_name': proc_name,
                            'details': {
                                'user': event.get('user', 'unknown'),
                                'command_line': event.get('command_line', 'N/A')
                            }
                        })
                        break
    
    def _detect_data_theft_attempts(self, events: List[Dict]) -> None:
        """Detect data theft and exfiltration attempts"""
        file_access = defaultdict(lambda: defaultdict(int))
        
        for event in events:
            if event.get('type') == 'file_access':
                user = event.get('user', 'unknown')
                access_type = event.get('access_type', 'unknown')
                file_access[user][access_type] += 1
        
        for user, access_types in file_access.items():
            total_access = sum(access_types.values())
            
            if total_access > self.THRESHOLDS['file_access_threshold']:
                self.alerts.append({
                    'type': 'DATA_THEFT_ATTEMPT',
                    'severity': AlertSeverity.WARNING.name,
                    'timestamp': datetime.now().isoformat(),
                    'description': f'Unusual file access pattern detected for user: {user}',
                    'user': user,
                    'details': {
                        'total_file_operations': total_access,
                        'threshold': self.THRESHOLDS['file_access_threshold'],
                        'access_breakdown': dict(access_types)
                    }
                })
    
    def _detect_unauthorized_access(self, events: List[Dict]) -> None:
        """Detect unauthorized access attempts"""
        access_denied = [
            e for e in events
            if e.get('type') == 'access_denied'
        ]
        
        denied_by_user = defaultdict(int)
        for event in access_denied:
            user = event.get('user', 'unknown')
            denied_by_user[user] += 1
        
        for user, count in denied_by_user.items():
            if count >= 10:  # Multiple access denied events
                self.alerts.append({
                    'type': 'UNAUTHORIZED_ACCESS_ATTEMPT',
                    'severity': AlertSeverity.WARNING.name,
                    'timestamp': datetime.now().isoformat(),
                    'description': f'Multiple unauthorized access attempts by user: {user}',
                    'user': user,
                    'details': {
                        'denied_attempts': count
                    }
                })
    
    def _calculate_threat_level(self) -> str:
        """Calculate overall system threat level"""
        if not self.alerts:
            return 'LOW'
        
        critical_count = sum(1 for a in self.alerts if a['severity'] == AlertSeverity.CRITICAL.name)
        warning_count = sum(1 for a in self.alerts if a['severity'] == AlertSeverity.WARNING.name)
        
        if critical_count >= 2:
            return 'CRITICAL'
        elif critical_count >= 1:
            return 'HIGH'
        elif warning_count >= 3:
            return 'HIGH'
        elif warning_count >= 1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_alert_summary(self) -> Dict:
        """Get summary of current alerts"""
        critical = sum(1 for a in self.alerts if a['severity'] == AlertSeverity.CRITICAL.name)
        warning = sum(1 for a in self.alerts if a['severity'] == AlertSeverity.WARNING.name)
        info = sum(1 for a in self.alerts if a['severity'] == AlertSeverity.INFO.name)
        
        return {
            'total_alerts': len(self.alerts),
            'critical_alerts': critical,
            'warning_alerts': warning,
            'info_alerts': info,
            'suspicious_ips_count': len(self.suspicious_ips),
            'threat_level': self._calculate_threat_level()
        }
    
    def clear_old_alerts(self, max_age_seconds: int = 3600) -> None:
        """Remove alerts older than specified time"""
        current_time = time.time()
        cutoff_time = current_time - max_age_seconds
        
        self.alerts = [
            a for a in self.alerts
            if a.get('timestamp') and
            datetime.fromisoformat(a['timestamp']).timestamp() >= cutoff_time
        ]
    
    def clear_old_events(self, max_age_seconds: int = 7200) -> None:
        """Remove events older than specified time"""
        current_time = time.time()
        cutoff_time = current_time - max_age_seconds
        
        self.event_log = [
            e for e in self.event_log
            if e.get('timestamp', current_time) >= cutoff_time
        ]
