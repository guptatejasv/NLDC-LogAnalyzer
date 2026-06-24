"""
Advanced Threat Hunting Analyzer Module
Performs sophisticated threat hunting analysis on network traffic patterns.
Includes: beaconing detection, C2 detection, lateral movement, data exfiltration, etc.
"""

import pandas as pd
import logging
import numpy as np
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Set
import json

logger = logging.getLogger(__name__)


class AdvancedAnalyzer:
    """Advanced threat hunting analysis engine"""
    
    # Known malicious port indicators
    MALICIOUS_PORTS = {
        # Remote Access / RDP / SSH Abuse
        3389: {"risk": "HIGH", "category": "Remote Access", "indicators": ["RDP Compromise", "Lateral Movement"]},
        22: {"risk": "MEDIUM", "category": "SSH", "indicators": ["SSH Brute Force", "Lateral Movement"]},
        5900: {"risk": "HIGH", "category": "VNC", "indicators": ["Remote Access", "Lateral Movement"]},
        
        # C2 / Malware Communication
        4444: {"risk": "HIGH", "category": "C2", "indicators": ["Metasploit", "C2 Communication"]},
        5555: {"risk": "HIGH", "category": "C2", "indicators": ["Android Debug Bridge", "C2"]},
        6667: {"risk": "HIGH", "category": "IRC", "indicators": ["IRC Botnet", "C2 Communication"]},
        8888: {"risk": "MEDIUM", "category": "HTTP Alt", "indicators": ["C2 Communication", "Unauthorized Access"]},
        9999: {"risk": "MEDIUM", "category": "Generic", "indicators": ["Malware Communication"]},
        
        # Web Shells / Backdoors
        8080: {"risk": "MEDIUM", "category": "HTTP Alt", "indicators": ["Web Shell", "Unauthorized Service"]},
        
        # DNS Tunneling
        53: {"risk": "MEDIUM", "category": "DNS", "indicators": ["DNS Tunneling", "Data Exfiltration"]},
        
        # Database / File Transfer
        1433: {"risk": "MEDIUM", "category": "MSSQL", "indicators": ["Database Access", "Lateral Movement"]},
        3306: {"risk": "MEDIUM", "category": "MySQL", "indicators": ["Database Access", "Lateral Movement"]},
        5432: {"risk": "MEDIUM", "category": "PostgreSQL", "indicators": ["Database Access", "Lateral Movement"]},
        20: {"risk": "MEDIUM", "category": "FTP", "indicators": ["File Transfer", "Data Exfiltration"]},
        21: {"risk": "MEDIUM", "category": "FTP", "indicators": ["File Transfer", "Data Exfiltration"]},
    }
    
    # Known benign ports
    BENIGN_PORTS = {80, 443, 8443, 53, 123, 25, 587, 465, 110, 143, 993, 995, 389, 636}
    
    # DNS tunneling patterns
    DNS_TUNNEL_INDICATORS = [
        "x64", "x86", "cmd", "powershell", "meterpreter", "dga", "ddns",
        "tunnel", "exfil", "c2", "beacon", "payload"
    ]
    
    # Telegram API servers (known)
    TELEGRAM_RANGES = ['149.154', '149.155']
    
    def __init__(self, df: pd.DataFrame, enriched_results: List[Dict] = None):
        """
        Initialize advanced analyzer
        
        Args:
            df: DataFrame with network logs
            enriched_results: List of enriched IP data for correlation
        """
        self.df = df
        self.enriched_results = enriched_results or []
        self.analysis_results = {}
        
        # Prepare data structures
        self._prepare_data()
        
        logger.info(f"AdvancedAnalyzer initialized with {len(df)} records")
    
    def _prepare_data(self):
        """Prepare data structures for analysis"""
        # Standardize column names
        if 'Destination IP' in self.df.columns:
            self.df['dest_ip'] = self.df['Destination IP']
        if 'Destination Port' in self.df.columns:
            self.df['dest_port'] = self.df['Destination Port']
        if 'Source IP' in self.df.columns:
            self.df['src_ip'] = self.df['Source IP']
        if 'Date' in self.df.columns:
            self.df['timestamp'] = pd.to_datetime(self.df['Date'], errors='coerce')
        if 'Action' in self.df.columns:
            self.df['action'] = self.df['Action'].str.lower()
        
        logger.debug("Data preparation complete")
    
    def run_all_analysis(self) -> Dict[str, Any]:
        """Run all advanced analysis modules"""
        logger.info("Starting complete advanced analysis")
        
        self.analysis_results = {
            'destination_analysis': self.analyze_destinations(),
            'communication_behavior': self.analyze_communication_behavior(),
            'beaconing_analysis': self.detect_beaconing(),
            'attack_patterns': self.detect_attack_patterns(),
            'port_analysis': self.analyze_ports(),
            'dns_analysis': self.analyze_dns_tunneling(),
            'telegram_analysis': self.analyze_telegram(),
            'denied_vs_allowed': self.analyze_denied_vs_allowed(),
            'lateral_movement': self.detect_lateral_movement(),
            'data_exfiltration': self.detect_data_exfiltration(),
            'c2_indicators': self.detect_c2_communication(),
        }
        
        logger.info("Complete advanced analysis finished")
        return self.analysis_results
    
    def analyze_destinations(self) -> Dict[str, Any]:
        """Analyze destination IPs and traffic patterns"""
        logger.info("Analyzing destinations")
        
        results = {
            'total_destinations': len(self.df['dest_ip'].unique()),
            'top_destinations': self.df['dest_ip'].value_counts().head(10).to_dict(),
            'destination_ports': self._get_destination_ports(),
            'top_countries': self._get_destination_countries(),
            'most_contacted_suspicious': self._get_suspicious_destinations(),
            'most_contacted_malicious': self._get_malicious_destinations(),
        }
        
        # Add findings
        results['findings'] = self._generate_destination_findings(results)
        
        return results
    
    def _get_destination_ports(self) -> Dict[int, int]:
        """Get frequency of destination ports"""
        try:
            port_counts = self.df['dest_port'].value_counts().head(20).to_dict()
            result = {}
            for p, c in port_counts.items():
                if pd.notna(p) and str(p).strip() and str(p).strip() != '(blank)':
                    try:
                        result[int(float(p))] = c
                    except (ValueError, TypeError):
                        pass
            return result
        except Exception as e:
            logger.error(f"Error analyzing ports: {e}")
            return {}
    
    def _get_destination_countries(self) -> List[Dict]:
        """Get top countries for destinations"""
        # This would integrate with MaxMind GeoIP in production
        # For now, return placeholder with indicator to enhance later
        return [
            {"country": "Unknown", "count": len(self.df), "note": "Requires GeoIP integration"}
        ]
    
    def _get_suspicious_destinations(self) -> Dict[str, int]:
        """Get most contacted IPs marked as suspicious"""
        suspicious_ips = set()
        for result in self.enriched_results:
            if result.get('classification') == 'SUSPICIOUS':
                suspicious_ips.add(result.get('ip'))
        
        if not suspicious_ips:
            return {}
        
        return self.df[self.df['dest_ip'].isin(suspicious_ips)]['dest_ip'].value_counts().head(10).to_dict()
    
    def _get_malicious_destinations(self) -> Dict[str, int]:
        """Get most contacted IPs marked as malicious"""
        malicious_ips = set()
        for result in self.enriched_results:
            if result.get('classification') == 'MALICIOUS':
                malicious_ips.add(result.get('ip'))
        
        if not malicious_ips:
            return {}
        
        return self.df[self.df['dest_ip'].isin(malicious_ips)]['dest_ip'].value_counts().head(10).to_dict()
    
    def _generate_destination_findings(self, results: Dict) -> List[str]:
        """Generate human-readable findings from destination analysis"""
        findings = []
        
        if results['total_destinations'] > 50:
            findings.append(f"Wide range of destinations ({results['total_destinations']} unique IPs) suggests reconnaissance or widespread infection")
        
        top_dest = results['top_destinations']
        if top_dest:
            top_ip = list(top_dest.keys())[0]
            count = top_dest[top_ip]
            findings.append(f"Top destination: {top_ip} ({count} connections)")
        
        if results['most_contacted_malicious']:
            findings.append(f"CRITICAL: {len(results['most_contacted_malicious'])} malicious IPs contacted")
        
        if results['most_contacted_suspicious']:
            findings.append(f"HIGH: {len(results['most_contacted_suspicious'])} suspicious IPs contacted")
        
        return findings
    
    def analyze_communication_behavior(self) -> Dict[str, Any]:
        """Analyze communication patterns and anomalies"""
        logger.info("Analyzing communication behavior")
        
        results = {
            'repeated_communication': self._detect_repeated_communication(),
            'persistent_outbound': self._detect_persistent_outbound(),
            'high_frequency_destinations': self._find_high_frequency_destinations(),
            'outlier_destinations': self._find_outlier_destinations(),
            'communication_concentration': self._analyze_communication_concentration(),
        }
        
        results['findings'] = self._generate_behavior_findings(results)
        
        return results
    
    def _detect_repeated_communication(self) -> Dict[str, int]:
        """Detect IPs contacted multiple times"""
        repeated = self.df['dest_ip'].value_counts()
        repeated = repeated[repeated > 1].to_dict()
        return dict(sorted(repeated.items(), key=lambda x: x[1], reverse=True)[:20])
    
    def _detect_persistent_outbound(self) -> Dict[str, int]:
        """Detect persistent outbound communication"""
        outbound = self.df[self.df.get('Connection Type', '').str.lower().str.contains('outbound|out', na=False)]
        if len(outbound) == 0:
            return {}
        
        persistence = outbound['dest_ip'].value_counts()
        return dict(sorted(persistence.items(), key=lambda x: x[1], reverse=True)[:20])
    
    def _find_high_frequency_destinations(self) -> Dict[str, int]:
        """Find destinations with abnormally high frequency"""
        freq = self.df['dest_ip'].value_counts()
        mean_freq = freq.mean()
        std_freq = freq.std()
        
        # Destinations with frequency > mean + 2*std
        high_freq_threshold = mean_freq + (2 * std_freq)
        high_freq = freq[freq > high_freq_threshold].to_dict()
        
        return dict(sorted(high_freq.items(), key=lambda x: x[1], reverse=True))
    
    def _find_outlier_destinations(self) -> Dict[str, Any]:
        """Find outlier destinations (contacted unusually few or many times)"""
        freq = self.df['dest_ip'].value_counts()
        
        outliers = {}
        for ip, count in freq.items():
            z_score = abs((count - freq.mean()) / (freq.std() + 0.001))
            if z_score > 3:  # Statistical outlier (>3 std deviations)
                outliers[ip] = {"count": int(count), "z_score": round(z_score, 2)}
        
        return dict(sorted(outliers.items(), key=lambda x: x[1]['z_score'], reverse=True)[:20])
    
    def _analyze_communication_concentration(self) -> Dict[str, Any]:
        """Analyze if communication is concentrated on small set of hosts"""
        freq = self.df['dest_ip'].value_counts()
        total = len(self.df)
        
        top_5_ips = freq.head(5)
        top_5_traffic = top_5_ips.sum() / total * 100
        
        return {
            'top_5_ips_percentage': round(top_5_traffic, 2),
            'concentration_ratio': round(top_5_traffic / (100/5), 2),  # Ratio to expected
            'interpretation': self._interpret_concentration(top_5_traffic),
        }
    
    def _interpret_concentration(self, percentage: float) -> str:
        """Interpret communication concentration"""
        if percentage > 80:
            return "CRITICAL: Highly concentrated communication (likely C2 or specific service)"
        elif percentage > 60:
            return "HIGH: Concentrated communication (potential C2 or limited services)"
        elif percentage > 40:
            return "MEDIUM: Moderately concentrated communication"
        else:
            return "LOW: Distributed communication (normal for legitimate traffic)"
    
    def _generate_behavior_findings(self, results: Dict) -> List[str]:
        """Generate behavioral findings"""
        findings = []
        
        if results['repeated_communication']:
            repeated_count = len(results['repeated_communication'])
            findings.append(f"Repeated communication detected with {repeated_count} unique destinations")
        
        if results['high_frequency_destinations']:
            hf_count = len(results['high_frequency_destinations'])
            findings.append(f"HIGH-FREQUENCY destinations identified ({hf_count} IPs with abnormal frequency)")
        
        if results['outlier_destinations']:
            findings.append(f"Statistical outliers detected ({len(results['outlier_destinations'])} anomalous IPs)")
        
        conc = results['communication_concentration']
        findings.append(f"Communication concentration: Top 5 IPs = {conc['top_5_ips_percentage']}% - {conc['interpretation']}")
        
        return findings
    
    def detect_beaconing(self) -> Dict[str, Any]:
        """Detect beacon-like communication patterns"""
        logger.info("Detecting beaconing patterns")
        
        results = {
            'possible_beacons': self._find_possible_beacons(),
            'interval_analysis': self._analyze_intervals(),
        }
        
        results['findings'] = self._generate_beacon_findings(results)
        
        return results
    
    def _find_possible_beacons(self) -> Dict[str, Any]:
        """Find IPs with beacon-like behavior"""
        if 'timestamp' not in self.df.columns or self.df['timestamp'].isna().all():
            logger.warning("No timestamp data available for beaconing analysis")
            return {}
        
        beacons = {}
        
        for dest_ip in self.df['dest_ip'].unique():
            ip_data = self.df[self.df['dest_ip'] == dest_ip].sort_values('timestamp')
            
            if len(ip_data) < 3:
                continue
            
            # Calculate intervals between communications
            times = ip_data['timestamp'].dropna()
            if len(times) < 2:
                continue
            
            intervals = []
            for i in range(1, len(times)):
                if pd.notna(times.iloc[i]) and pd.notna(times.iloc[i-1]):
                    delta = (times.iloc[i] - times.iloc[i-1]).total_seconds()
                    if delta > 0:
                        intervals.append(delta)
            
            if len(intervals) < 2:
                continue
            
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            cv = std_interval / (mean_interval + 0.001)  # Coefficient of variation
            
            # Beacons have low coefficient of variation (regular intervals)
            if cv < 0.3 and mean_interval > 10:  # Regular intervals, not too frequent
                confidence = max(0, 1.0 - cv)
                beacons[dest_ip] = {
                    'mean_interval_seconds': round(mean_interval, 2),
                    'std_deviation': round(std_interval, 2),
                    'coefficient_variation': round(cv, 3),
                    'confidence': round(confidence, 2),
                    'contact_count': len(ip_data),
                    'possible_intervals': self._interpret_beacon_interval(mean_interval),
                }
        
        return dict(sorted(beacons.items(), key=lambda x: x[1]['confidence'], reverse=True))
    
    def _interpret_beacon_interval(self, seconds: float) -> str:
        """Interpret beacon interval"""
        if seconds < 60:
            return "Every 30 seconds (high frequency)"
        elif seconds < 120:
            return "Every 60 seconds"
        elif seconds < 300:
            return "Every 5 minutes"
        elif seconds < 600:
            return "Every 10 minutes"
        elif seconds < 1800:
            return "Every 30 minutes"
        else:
            return f"Every {int(seconds/60)} minutes"
    
    def _analyze_intervals(self) -> Dict[str, Any]:
        """Analyze communication intervals"""
        if 'timestamp' not in self.df.columns:
            return {}
        
        # Group by destination IP
        interval_stats = {}
        for dest_ip in self.df['dest_ip'].unique():
            ip_data = self.df[self.df['dest_ip'] == dest_ip].sort_values('timestamp')
            times = ip_data['timestamp'].dropna()
            
            if len(times) >= 2:
                intervals = []
                for i in range(1, len(times)):
                    delta = (times.iloc[i] - times.iloc[i-1]).total_seconds()
                    if delta > 0:
                        intervals.append(delta)
                
                if intervals:
                    interval_stats[dest_ip] = {
                        'min': round(min(intervals), 2),
                        'max': round(max(intervals), 2),
                        'mean': round(np.mean(intervals), 2),
                        'median': round(np.median(intervals), 2),
                    }
        
        return interval_stats
    
    def _generate_beacon_findings(self, results: Dict) -> List[str]:
        """Generate beacon findings"""
        findings = []
        
        if results['possible_beacons']:
            findings.append(f"CRITICAL: {len(results['possible_beacons'])} possible C2 beacon(s) detected")
            
            for ip, data in list(results['possible_beacons'].items())[:3]:
                findings.append(f"  • {ip}: {data['possible_intervals']} (confidence: {data['confidence']})")
        
        return findings
    
    def detect_attack_patterns(self) -> Dict[str, Any]:
        """Detect attack-like patterns"""
        logger.info("Detecting attack patterns")
        
        results = {
            'malware_indicators': self._detect_malware_patterns(),
            'c2_indicators': self._detect_c2_patterns(),
            'exfiltration_patterns': self._detect_exfiltration_patterns(),
            'reconnaissance_patterns': self._detect_reconnaissance(),
            'lateral_movement_indicators': self._detect_lateral_movement_patterns(),
        }
        
        results['findings'] = self._generate_attack_findings(results)
        
        return results
    
    def _detect_malware_patterns(self) -> Dict[str, float]:
        """Detect malware communication patterns"""
        patterns = {}
        
        # Pattern 1: High volume to single IP
        freq = self.df['dest_ip'].value_counts()
        if len(freq) > 0 and freq.iloc[0] > 50:
            top_ip = freq.index[0]
            patterns[f'High volume to single IP ({top_ip})'] = 0.8
        
        # Pattern 2: Denied connections pattern
        denied = self.df[self.df['action'].isin(['deny', 'denied', 'drop'])]
        if len(denied) > len(self.df) * 0.5:  # More than 50% denied
            patterns['Abnormally high denied rate'] = 0.7
        
        return patterns
    
    def _detect_c2_patterns(self) -> Dict[str, float]:
        """Detect C2 communication patterns"""
        patterns = {}
        
        # Pattern 1: Regular communication intervals
        if self.analysis_results.get('beaconing_analysis', {}).get('possible_beacons'):
            patterns['Beaconing behavior detected'] = 0.95
        
        # Pattern 2: Communication to known C2 IPs (via enrichment)
        c2_ips = set()
        for result in self.enriched_results:
            if 'c2' in str(result.get('virustotal', {})).lower() or \
               'c2' in str(result.get('abuseipdb', {})).lower():
                c2_ips.add(result.get('ip'))
        
        if c2_ips and len(self.df[self.df['dest_ip'].isin(c2_ips)]) > 0:
            patterns['Communication to known C2 infrastructure'] = 0.95
        
        return patterns
    
    def _detect_exfiltration_patterns(self) -> Dict[str, float]:
        """Detect data exfiltration patterns"""
        patterns = {}
        
        # Pattern 1: Large data transfer indicators
        if len(self.df) > 100:
            patterns['High volume outbound traffic'] = 0.6
        
        # Pattern 2: Communication to external rare IPs
        top_ips = set(self.df['dest_ip'].value_counts().head(5).index)
        rare_destinations = self.df[~self.df['dest_ip'].isin(top_ips)]['dest_ip'].nunique()
        
        if rare_destinations > len(self.df) * 0.2:
            patterns['Communication to many rare destinations'] = 0.65
        
        return patterns
    
    def _detect_reconnaissance(self) -> Dict[str, float]:
        """Detect reconnaissance patterns"""
        patterns = {}
        
        # Pattern 1: Many unique destinations
        unique_dests = self.df['dest_ip'].nunique()
        total_records = len(self.df)
        
        if unique_dests / total_records > 0.7:
            patterns['Scanning-like behavior (many unique destinations)'] = 0.7
        
        # Pattern 2: Port diversity
        if 'dest_port' in self.df.columns:
            unique_ports = self.df['dest_port'].nunique()
            if unique_ports > 20:
                patterns['Port scanning pattern detected'] = 0.8
        
        return patterns
    
    def _detect_lateral_movement_patterns(self) -> Dict[str, float]:
        """Detect lateral movement patterns"""
        patterns = {}
        
        # Pattern 1: Communication between internal IPs
        try:
            internal_pattern = r'^(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)'
            internal_sources = self.df[self.df['src_ip'].str.contains(internal_pattern, na=False, regex=True)]
            
            if len(internal_sources) > 0:
                internal_dests = internal_sources[
                    internal_sources['dest_ip'].str.contains(internal_pattern, na=False, regex=True)
                ]
                
                if len(internal_dests) > 0:
                    patterns['Internal-to-internal communication detected'] = 0.7
        except Exception as e:
            logger.debug(f"Error detecting lateral movement: {e}")
        
        # Pattern 2: Suspicious internal ports
        suspicious_ports_in_traffic = []
        try:
            for port in self.MALICIOUS_PORTS.keys():
                if port in self.df.get('dest_port', pd.Series([])).values:
                    suspicious_ports_in_traffic.append(port)
        except Exception as e:
            logger.debug(f"Error checking suspicious ports: {e}")
        
        if suspicious_ports_in_traffic:
            patterns[f'Suspicious ports detected ({", ".join(map(str, suspicious_ports_in_traffic[:3]))})'] = 0.8
        
        return patterns
    
    def _generate_attack_findings(self, results: Dict) -> List[str]:
        """Generate attack pattern findings"""
        findings = []
        
        for pattern_type, patterns in results.items():
            if isinstance(patterns, dict) and patterns:
                findings.append(f"{pattern_type.replace('_', ' ').title()}: Detected")
                for pattern, score in list(patterns.items())[:3]:
                    findings.append(f"  • {pattern} (confidence: {score})")
        
        return findings
    
    def analyze_ports(self) -> Dict[str, Any]:
        """Analyze destination ports for malicious indicators"""
        logger.info("Analyzing ports")
        
        if 'dest_port' not in self.df.columns:
            return {'findings': ['Port data not available in logs']}
        
        results = {
            'top_ports': self.df['dest_port'].value_counts().head(20).to_dict(),
            'malicious_ports_detected': self._detect_malicious_ports(),
            'unusual_ports': self._detect_unusual_ports(),
        }
        
        results['findings'] = self._generate_port_findings(results)
        
        return results
    
    def _detect_malicious_ports(self) -> Dict[int, Dict]:
        """Detect traffic to known malicious ports"""
        malicious = {}
        
        for port in self.df['dest_port'].unique():
            if pd.notna(port):
                port_int = int(port) if isinstance(port, (int, float)) else None
                if port_int and port_int in self.MALICIOUS_PORTS:
                    count = len(self.df[self.df['dest_port'] == port])
                    malicious[port_int] = {
                        'count': count,
                        'info': self.MALICIOUS_PORTS[port_int],
                    }
        
        return malicious
    
    def _detect_unusual_ports(self) -> Dict[int, Dict]:
        """Detect unusual port usage"""
        unusual = {}
        
        port_freq = self.df['dest_port'].value_counts()
        mean_freq = port_freq.mean()
        std_freq = port_freq.std()
        threshold = mean_freq + (2 * std_freq)
        
        for port, count in port_freq.items():
            if pd.notna(port) and count > threshold:
                port_int = int(port) if isinstance(port, (int, float)) else None
                if port_int and port_int not in self.BENIGN_PORTS:
                    unusual[port_int] = {'count': count, 'frequency': 'abnormally high'}
        
        return unusual
    
    def _generate_port_findings(self, results: Dict) -> List[str]:
        """Generate port analysis findings"""
        findings = []
        
        if results['malicious_ports_detected']:
            findings.append(f"CRITICAL: Malicious ports detected ({len(results['malicious_ports_detected'])} ports)")
            for port, data in list(results['malicious_ports_detected'].items())[:5]:
                findings.append(f"  • Port {port}: {data['info']['category']} ({data['count']} connections)")
        
        if results['unusual_ports']:
            findings.append(f"HIGH: Unusual port usage detected ({len(results['unusual_ports'])} ports with abnormal frequency)")
        
        return findings
    
    def analyze_dns_tunneling(self) -> Dict[str, Any]:
        """Analyze for DNS tunneling indicators"""
        logger.info("Analyzing DNS patterns")
        
        # This would require DNS query data, which isn't in the basic logs
        return {
            'findings': ['DNS analysis requires DNS query logs - not available in network flow data'],
            'note': 'To enable DNS tunneling detection, provide DNS query logs or integrate with DNS security system'
        }
    
    def analyze_telegram(self) -> Dict[str, Any]:
        """Analyze Telegram communication patterns"""
        logger.info("Analyzing Telegram usage")
        
        results = {
            'telegram_contacts': self._find_telegram_contacts(),
            'telegram_frequency': {},
            'telegram_timing': self._analyze_telegram_timing(),
        }
        
        results['findings'] = self._generate_telegram_findings(results)
        
        return results
    
    def _find_telegram_contacts(self) -> Dict[str, int]:
        """Find Telegram server contacts"""
        telegram_traffic = {}
        
        for ip in self.df['dest_ip'].unique():
            ip_str = str(ip)
            for telegram_range in self.TELEGRAM_RANGES:
                if ip_str.startswith(telegram_range):
                    count = len(self.df[self.df['dest_ip'] == ip])
                    telegram_traffic[ip] = count
        
        return dict(sorted(telegram_traffic.items(), key=lambda x: x[1], reverse=True))
    
    def _analyze_telegram_timing(self) -> Dict[str, Any]:
        """Analyze timing of Telegram traffic"""
        if not self._find_telegram_contacts():
            return {}
        
        telegram_traffic = self.df[
            self.df['dest_ip'].str.startswith('149.154', na=False) |
            self.df['dest_ip'].str.startswith('149.155', na=False)
        ]
        
        if len(telegram_traffic) == 0:
            return {}
        
        if 'timestamp' in telegram_traffic.columns:
            first_contact = telegram_traffic['timestamp'].min()
            last_contact = telegram_traffic['timestamp'].max()
            
            return {
                'first_contact': str(first_contact),
                'last_contact': str(last_contact),
                'duration': str(last_contact - first_contact) if pd.notna(first_contact) and pd.notna(last_contact) else 'Unknown',
            }
        
        return {}
    
    def _generate_telegram_findings(self, results: Dict) -> List[str]:
        """Generate Telegram analysis findings"""
        findings = []
        
        if results['telegram_contacts']:
            findings.append(f"Telegram API traffic detected ({len(results['telegram_contacts'])} connections)")
            findings.append(f"  • Risk Level: MEDIUM (Telegram can be used for C2 or exfiltration)")
        else:
            findings.append("No Telegram API traffic detected")
        
        return findings
    
    def analyze_denied_vs_allowed(self) -> Dict[str, Any]:
        """Analyze allowed vs denied connections"""
        logger.info("Analyzing allowed vs denied traffic")
        
        results = {
            'total_records': len(self.df),
        }
        
        if 'action' in self.df.columns:
            action_counts = self.df['action'].value_counts(normalize=False).to_dict()
            action_pct = self.df['action'].value_counts(normalize=True).to_dict()
            
            results['action_counts'] = action_counts
            results['action_percentage'] = {k: round(v * 100, 2) for k, v in action_pct.items()}
        
        results['findings'] = self._generate_denied_allowed_findings(results)
        
        return results
    
    def _generate_denied_allowed_findings(self, results: Dict) -> List[str]:
        """Generate denied vs allowed findings"""
        findings = []
        
        if 'action_percentage' in results:
            pct = results['action_percentage']
            
            denied_count = sum(v for k, v in pct.items() if 'deny' in k.lower() or 'drop' in k.lower())
            
            if denied_count > 80:
                findings.append(f"CRITICAL: {denied_count}% of traffic was denied/dropped by security controls")
                findings.append("  → Indicates successful traffic blocking or network segmentation")
            elif denied_count > 50:
                findings.append(f"HIGH: {denied_count}% of traffic was denied/dropped")
                findings.append("  → Strong security posture; most malicious attempts were blocked")
            elif denied_count > 20:
                findings.append(f"MEDIUM: {denied_count}% of traffic was denied")
                findings.append("  → Some malicious attempts were blocked")
            else:
                findings.append(f"LOW: Only {denied_count}% of traffic was denied")
                findings.append("  → Most traffic was allowed; monitor for unauthorized connections")
        
        return findings
    
    def detect_lateral_movement(self) -> Dict[str, Any]:
        """Detect lateral movement indicators"""
        logger.info("Detecting lateral movement")
        
        results = {
            'internal_communications': self._find_internal_communications(),
            'suspicious_port_usage': self._find_suspicious_port_usage(),
        }
        
        results['findings'] = self._generate_lateral_movement_findings(results)
        
        return results
    
    def _find_internal_communications(self) -> Dict[str, Any]:
        """Find internal IP to internal IP communication"""
        try:
            internal_pattern = r'^(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)'
            
            internal_src = self.df[self.df['src_ip'].str.contains(internal_pattern, na=False, regex=True)]
            internal_dest = internal_src[internal_src['dest_ip'].str.contains(internal_pattern, na=False, regex=True)]
            
            if len(internal_dest) == 0:
                return {}
            
            return {
                'count': len(internal_dest),
                'unique_source_ips': internal_dest['src_ip'].nunique(),
                'unique_dest_ips': internal_dest['dest_ip'].nunique(),
                'top_communications': internal_dest.groupby(['src_ip', 'dest_ip']).size().nlargest(5).to_dict(),
            }
        except Exception as e:
            logger.debug(f"Error finding internal communications: {e}")
            return {}
    
    def _find_suspicious_port_usage(self) -> Dict[int, Dict]:
        """Find suspicious port usage in traffic"""
        suspicious = {}
        
        if 'dest_port' not in self.df.columns:
            return {}
        
        for port, info in self.MALICIOUS_PORTS.items():
            if port in self.df['dest_port'].values:
                count = len(self.df[self.df['dest_port'] == port])
                suspicious[port] = {'count': count, 'risk': info['risk'], 'category': info['category']}
        
        return suspicious
    
    def _generate_lateral_movement_findings(self, results: Dict) -> List[str]:
        """Generate lateral movement findings"""
        findings = []
        
        if results['internal_communications'] and results['internal_communications'].get('count', 0) > 0:
            count = results['internal_communications']['count']
            findings.append(f"Internal lateral movement detected ({count} internal-to-internal connections)")
        
        if results['suspicious_port_usage']:
            findings.append(f"Suspicious port usage detected on internal network ({len(results['suspicious_port_usage'])} ports)")
        
        return findings
    
    def detect_data_exfiltration(self) -> Dict[str, Any]:
        """Detect data exfiltration indicators"""
        logger.info("Detecting data exfiltration indicators")
        
        results = {
            'high_volume_destinations': self._find_high_volume_destinations(),
            'rare_destination_contacts': self._find_rare_destination_contacts(),
        }
        
        results['findings'] = self._generate_exfiltration_findings(results)
        
        return results
    
    def _find_high_volume_destinations(self) -> Dict[str, int]:
        """Find destinations with unusually high traffic volume"""
        freq = self.df['dest_ip'].value_counts()
        
        if len(freq) == 0:
            return {}
        
        mean_freq = freq.mean()
        std_freq = freq.std()
        threshold = mean_freq + (3 * std_freq)
        
        high_volume = freq[freq > threshold].to_dict()
        
        return dict(sorted(high_volume.items(), key=lambda x: x[1], reverse=True))
    
    def _find_rare_destination_contacts(self) -> Dict[str, int]:
        """Find one-time or rare destination contacts"""
        freq = self.df['dest_ip'].value_counts()
        
        if len(freq) == 0:
            return {}
        
        rare = freq[freq == 1].to_dict()
        sorted_rare = dict(sorted(rare.items(), key=lambda x: x[1]))
        # Return only first 50 items
        return dict(list(sorted_rare.items())[:50])
    
    def _generate_exfiltration_findings(self, results: Dict) -> List[str]:
        """Generate exfiltration findings"""
        findings = []
        
        if results['high_volume_destinations']:
            findings.append(f"High-volume data transfer patterns detected ({len(results['high_volume_destinations'])} destinations)")
        
        if results['rare_destination_contacts']:
            findings.append(f"One-time contact with rare destinations ({len(results['rare_destination_contacts'])} IPs)")
        
        return findings
    
    def detect_c2_communication(self) -> Dict[str, Any]:
        """Detect C2 communication indicators"""
        logger.info("Detecting C2 communication")
        
        results = {
            'known_c2_contacts': self._find_known_c2(),
            'beaconing_behavior': bool(self.analysis_results.get('beaconing_analysis', {}).get('possible_beacons')),
            'malicious_infrastructure': self._find_malicious_infrastructure(),
        }
        
        results['findings'] = self._generate_c2_findings(results)
        
        return results
    
    def _find_known_c2(self) -> Dict[str, Dict]:
        """Find known C2 infrastructure from enriched data"""
        c2_ips = {}
        
        for result in self.enriched_results:
            if result.get('classification') == 'MALICIOUS':
                ip = result.get('ip')
                count = len(self.df[self.df['dest_ip'] == ip])
                if count > 0:
                    c2_ips[ip] = {
                        'count': count,
                        'threat_type': result.get('threat_type', 'Unknown'),
                    }
        
        return c2_ips
    
    def _find_malicious_infrastructure(self) -> Dict[str, Dict]:
        """Find malicious infrastructure indicators"""
        infrastructure = {}
        
        # Check for CDN abuse
        for result in self.enriched_results:
            if result.get('classification') in ['SUSPICIOUS', 'POLICY_VIOLATION']:
                ip = result.get('ip')
                count = len(self.df[self.df['dest_ip'] == ip])
                if count > 2:  # Multiple contacts suggest active use
                    infrastructure[ip] = {
                        'classification': result.get('classification'),
                        'count': count,
                    }
        
        return infrastructure
    
    def _generate_c2_findings(self, results: Dict) -> List[str]:
        """Generate C2 communication findings"""
        findings = []
        
        if results['known_c2_contacts']:
            findings.append(f"CRITICAL: Communication to known C2 infrastructure detected ({len(results['known_c2_contacts'])} IPs)")
        
        if results['beaconing_behavior']:
            findings.append("CRITICAL: Beacon-like communication patterns detected (possible C2)")
        
        if results['malicious_infrastructure']:
            findings.append(f"HIGH: Malicious infrastructure contacted ({len(results['malicious_infrastructure'])} IPs)")
        
        return findings
    
    def get_risk_indicators(self) -> Dict[str, float]:
        """Generate overall risk indicators"""
        indicators = {}
        
        # Indicator 1: Denied traffic ratio
        if 'action' in self.df.columns:
            denied = self.df[self.df['action'].str.lower().str.contains('deny|drop', na=False)]
            denied_ratio = len(denied) / len(self.df) if len(self.df) > 0 else 0
            indicators['denied_traffic_ratio'] = denied_ratio
        
        # Indicator 2: Malicious IP contact frequency
        malicious_count = len([r for r in self.enriched_results if r.get('classification') == 'MALICIOUS'])
        indicators['malicious_ip_contacts'] = len(self.df[self.df['dest_ip'].isin([r.get('ip') for r in self.enriched_results if r.get('classification') == 'MALICIOUS'])])
        
        # Indicator 3: Beaconing confidence
        beacons = self.analysis_results.get('beaconing_analysis', {}).get('possible_beacons', {})
        if beacons:
            highest_confidence = max([b.get('confidence', 0) for b in beacons.values()])
            indicators['beaconing_confidence'] = highest_confidence
        
        return indicators
