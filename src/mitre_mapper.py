"""
MITRE ATT&CK Mapping Module
Maps threat indicators to MITRE ATT&CK techniques
"""

import logging
from typing import Dict, List, Any, Tuple

logger = logging.getLogger(__name__)


class MITREMapper:
    """Maps threat findings to MITRE ATT&CK framework"""
    
    # Technique mappings
    TECHNIQUE_DB = {
        'T1071': {
            'name': 'Application Layer Protocol',
            'tactic': 'Command and Control',
            'description': 'Adversaries may communicate using OSI application layer protocols',
            'indicators': ['c2_communication', 'beaconing', 'http_based_c2'],
        },
        'T1041': {
            'name': 'Exfiltration Over C2 Channel',
            'tactic': 'Exfiltration',
            'description': 'Adversaries may steal data by exfiltrating it over a command and control channel',
            'indicators': ['data_exfiltration', 'c2_communication', 'high_volume_outbound'],
        },
        'T1048': {
            'name': 'Exfiltration Over Alternative Protocol',
            'tactic': 'Exfiltration',
            'description': 'Adversaries may steal data by exfiltrating it over non-standard protocols',
            'indicators': ['dns_tunneling', 'icmp_tunneling', 'alternative_protocols'],
        },
        'T1005': {
            'name': 'Data from Local System',
            'tactic': 'Collection',
            'description': 'Adversaries may search local system sources for files containing sensitive information',
            'indicators': ['file_access_patterns', 'credential_dumping'],
        },
        'T1087': {
            'name': 'Account Discovery',
            'tactic': 'Discovery',
            'description': 'Adversaries may attempt to get a listing of valid accounts',
            'indicators': ['reconnaissance', 'account_enumeration', 'ldap_queries'],
        },
        'T1046': {
            'name': 'Network Service Scanning',
            'tactic': 'Discovery',
            'description': 'Adversaries may attempt to get information about services running on remote systems',
            'indicators': ['port_scanning', 'port_diversity', 'service_enumeration'],
        },
        'T1518': {
            'name': 'Software Discovery',
            'tactic': 'Discovery',
            'description': 'Adversaries may attempt to enumerate software and versions installed on a target system',
            'indicators': ['version_queries', 'software_enumeration', 'registry_queries'],
        },
        'T1021': {
            'name': 'Remote Services',
            'tactic': 'Lateral Movement',
            'description': 'Adversaries may use valid credentials to log into remote services to laterally move',
            'indicators': ['ssh_traffic', 'rdp_traffic', 'internal_communications', 'suspicious_ports'],
        },
        'T1570': {
            'name': 'Lateral Tool Transfer',
            'tactic': 'Lateral Movement',
            'description': 'Adversaries may transfer tools between systems during lateral movement',
            'indicators': ['file_transfer', 'internal_traffic', 'scp_sftp'],
        },
        'T1090': {
            'name': 'Proxy',
            'tactic': 'Command and Control',
            'description': 'Adversaries may use a proxy to relay communications to their C2 infrastructure',
            'indicators': ['proxy_traffic', 'vpn_connections', 'proxy_protocols'],
        },
        'T1572': {
            'name': 'Protocol Tunneling',
            'tactic': 'Command and Control',
            'description': 'Adversaries may tunnel network communications to and from a victim system',
            'indicators': ['dns_tunneling', 'icmp_tunneling', 'gre_tunnels'],
        },
        'T1008': {
            'name': 'Fallback Channels',
            'tactic': 'Command and Control',
            'description': 'Adversaries may use fallback or alternate communication channels',
            'indicators': ['c2_redundancy', 'multiple_c2', 'backup_infrastructure'],
        },
        'T1105': {
            'name': 'Ingress Tool Transfer',
            'tactic': 'Command and Control',
            'description': 'Adversaries may transfer tools or other files from an external system',
            'indicators': ['malware_download', 'payload_transfer', 'file_download'],
        },
        'T1571': {
            'name': 'Non-Standard Port',
            'tactic': 'Command and Control',
            'description': 'Adversaries may communicate using non-standard ports',
            'indicators': ['unusual_ports', 'malicious_ports', 'port_anomalies'],
        },
        'T1573': {
            'name': 'Encrypted Channel',
            'tactic': 'Command and Control',
            'description': 'Adversaries may encrypt command and control traffic',
            'indicators': ['https_c2', 'encrypted_traffic', 'ssl_tls_abuse'],
        },
        'T1140': {
            'name': 'Deobfuscate/Decode Files or Information',
            'tactic': 'Defense Evasion',
            'description': 'Adversaries may use techniques to obfuscate command and control communications',
            'indicators': ['encrypted_payloads', 'obfuscated_traffic', 'encoding'],
        },
        'T1090': {
            'name': 'Proxy',
            'tactic': 'Command and Control, Exfiltration',
            'description': 'Adversaries may use a proxy to relay communications',
            'indicators': ['proxy_usage', 'proxy_chain', 'vpn_abuse'],
        },
        'T1583': {
            'name': 'Acquire Infrastructure',
            'tactic': 'Resource Development',
            'description': 'Adversaries may buy, lease, or rent infrastructure for C2',
            'indicators': ['newly_registered_domains', 'vps_connections', 'hosting_provider_connections'],
        },
        'T1584': {
            'name': 'Compromise Infrastructure',
            'tactic': 'Resource Development',
            'description': 'Adversaries may compromise infrastructure to conduct operations',
            'indicators': ['compromised_server', 'botnet_nodes', 'hijacked_infrastructure'],
        },
    }
    
    def __init__(self, advanced_analysis: Dict = None, enriched_results: List[Dict] = None):
        """
        Initialize MITRE mapper
        
        Args:
            advanced_analysis: Advanced analysis results
            enriched_results: Enriched threat intelligence
        """
        self.advanced_analysis = advanced_analysis or {}
        self.enriched_results = enriched_results or []
        self.mapped_techniques = []
    
    def map_all_findings(self) -> List[Dict]:
        """Map all findings to MITRE techniques"""
        logger.info("Mapping findings to MITRE ATT&CK framework")
        
        self.mapped_techniques = []
        
        # Analyze each finding category
        self._map_c2_findings()
        self._map_exfiltration_findings()
        self._map_lateral_movement_findings()
        self._map_reconnaissance_findings()
        self._map_discovery_findings()
        
        logger.info(f"Mapped {len(self.mapped_techniques)} MITRE techniques")
        
        return self.mapped_techniques
    
    def _map_c2_findings(self):
        """Map C2-related findings"""
        c2_findings = self.advanced_analysis.get('c2_indicators', {})
        
        if c2_findings.get('known_c2_contacts'):
            self._add_mapping('T1071', 'CONFIRMED', 
                f"Known C2 infrastructure contacted: {len(c2_findings.get('known_c2_contacts', {}))} IPs",
                c2_findings.get('known_c2_contacts'))
        
        beacons = self.advanced_analysis.get('beaconing_analysis', {}).get('possible_beacons', {})
        if beacons:
            self._add_mapping('T1571', 'HIGH',
                f"Beaconing behavior detected: {len(beacons)} possible beacons",
                beacons)
    
    def _map_exfiltration_findings(self):
        """Map exfiltration-related findings"""
        exfil = self.advanced_analysis.get('data_exfiltration', {})
        
        if exfil.get('high_volume_destinations'):
            self._add_mapping('T1041', 'HIGH',
                f"High-volume data transfer detected: {len(exfil.get('high_volume_destinations', {}))} IPs",
                exfil.get('high_volume_destinations'))
        
        # Check for DNS tunneling
        dns_analysis = self.advanced_analysis.get('dns_analysis', {})
        if dns_analysis.get('tunneling_indicators'):
            self._add_mapping('T1048', 'HIGH',
                'Possible DNS tunneling detected',
                dns_analysis.get('tunneling_indicators'))
    
    def _map_lateral_movement_findings(self):
        """Map lateral movement findings"""
        lateral = self.advanced_analysis.get('lateral_movement', {})
        
        if lateral.get('internal_communications') and lateral['internal_communications'].get('count', 0) > 0:
            self._add_mapping('T1021', 'MEDIUM',
                f"Internal lateral movement: {lateral['internal_communications'].get('count')} connections",
                lateral.get('internal_communications'))
        
        if lateral.get('suspicious_port_usage'):
            self._add_mapping('T1570', 'MEDIUM',
                f"Suspicious internal port usage: {len(lateral.get('suspicious_port_usage', {}))} ports",
                lateral.get('suspicious_port_usage'))
    
    def _map_reconnaissance_findings(self):
        """Map reconnaissance-related findings"""
        patterns = self.advanced_analysis.get('attack_patterns', {})
        recon = patterns.get('reconnaissance_patterns', {})
        
        if recon.get('Scanning-like behavior (many unique destinations)'):
            self._add_mapping('T1046', 'MEDIUM',
                'Network service scanning behavior detected',
                recon)
        
        if recon.get('Port scanning pattern detected'):
            self._add_mapping('T1046', 'HIGH',
                'Active port scanning detected',
                recon)
    
    def _map_discovery_findings(self):
        """Map discovery-related findings"""
        comm_behavior = self.advanced_analysis.get('communication_behavior', {})
        outliers = comm_behavior.get('outlier_destinations', {})
        
        if len(outliers) > 5:
            self._add_mapping('T1518', 'MEDIUM',
                f'Network reconnaissance: {len(outliers)} outlier destinations',
                outliers)
    
    def _add_mapping(self, technique_id: str, confidence: str, evidence: str, details: Any = None):
        """Add a mapping to the results"""
        if technique_id not in self.TECHNIQUE_DB:
            return
        
        technique = self.TECHNIQUE_DB[technique_id]
        
        self.mapped_techniques.append({
            'technique_id': technique_id,
            'technique_name': technique['name'],
            'tactic': technique['tactic'],
            'description': technique['description'],
            'confidence': confidence,
            'evidence': evidence,
            'details': details,
        })
    
    def get_mitre_summary(self) -> Dict[str, Any]:
        """Get MITRE mapping summary"""
        if not self.mapped_techniques:
            self.map_all_findings()
        
        # Group by tactic
        by_tactic = {}
        for technique in self.mapped_techniques:
            tactic = technique['tactic']
            if tactic not in by_tactic:
                by_tactic[tactic] = []
            by_tactic[tactic].append(technique)
        
        # Count by confidence
        confidence_counts = {
            'CONFIRMED': sum(1 for t in self.mapped_techniques if t['confidence'] == 'CONFIRMED'),
            'HIGH': sum(1 for t in self.mapped_techniques if t['confidence'] == 'HIGH'),
            'MEDIUM': sum(1 for t in self.mapped_techniques if t['confidence'] == 'MEDIUM'),
            'LOW': sum(1 for t in self.mapped_techniques if t['confidence'] == 'LOW'),
        }
        
        return {
            'total_techniques': len(self.mapped_techniques),
            'by_tactic': by_tactic,
            'confidence_counts': confidence_counts,
            'techniques': self.mapped_techniques,
        }
