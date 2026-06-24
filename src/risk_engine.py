"""
Risk Scoring Engine Module
Calculates overall risk scores and severity assessments based on threat data
"""

import logging
from typing import Dict, List, Any, Tuple

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """Calculates risk scores and severity levels for threats"""
    
    def __init__(self, enriched_results: List[Dict], advanced_analysis: Dict):
        """
        Initialize risk scoring engine
        
        Args:
            enriched_results: List of enriched IP data with classifications
            advanced_analysis: Advanced threat analysis results
        """
        self.enriched_results = enriched_results
        self.advanced_analysis = advanced_analysis
        self.overall_score = 0
        self.severity = 'LOW'
        self.host_scores = {}
    
    def calculate_overall_risk(self) -> Tuple[int, str]:
        """
        Calculate overall risk score and severity
        
        Returns:
            Tuple of (risk_score: 0-100, severity: CRITICAL/HIGH/MEDIUM/LOW)
        """
        try:
            # Count threats by classification
            malicious_count = len([r for r in self.enriched_results if r.get('classification') == 'MALICIOUS'])
            suspicious_count = len([r for r in self.enriched_results if r.get('classification') == 'SUSPICIOUS'])
            total_ips = len(self.enriched_results)
            
            # Get analysis metrics
            beacons = len(self.advanced_analysis.get('beaconing_analysis', {}).get('possible_beacons', {}))
            c2_count = len(self.advanced_analysis.get('c2_indicators', {}).get('known_c2_contacts', {}))
            lateral_movement_count = len(self.advanced_analysis.get('lateral_movement', {}).get('suspicious_port_usage', {}))
            attack_patterns = len(self.advanced_analysis.get('attack_patterns', {}).get('malware_indicators', {}))
            
            # Base score from malicious IPs (0-40 points)
            malicious_percentage = (malicious_count / max(total_ips, 1)) * 100
            malicious_score = min(40, malicious_percentage / 2.5)
            
            # Suspicious IPs contribute (0-20 points)
            suspicious_percentage = (suspicious_count / max(total_ips, 1)) * 100
            suspicious_score = min(20, suspicious_percentage / 5)
            
            # Beaconing detection (0-15 points)
            beacon_score = min(15, beacons * 3)
            
            # C2 communication (0-15 points)
            c2_score = min(15, c2_count * 2)
            
            # Lateral movement (0-10 points)
            lateral_score = min(10, lateral_movement_count * 1.5)
            
            # Attack patterns (0-5 points)
            pattern_score = min(5, attack_patterns)
            
            # Calculate total score
            self.overall_score = int(malicious_score + suspicious_score + beacon_score + 
                                    c2_score + lateral_score + pattern_score)
            self.overall_score = min(100, max(0, self.overall_score))
            
            # Determine severity level
            if self.overall_score >= 80:
                self.severity = 'CRITICAL'
            elif self.overall_score >= 60:
                self.severity = 'HIGH'
            elif self.overall_score >= 40:
                self.severity = 'MEDIUM'
            else:
                self.severity = 'LOW'
            
            logger.info(f"Overall risk score calculated: {self.overall_score} ({self.severity})")
            logger.info(f"  - Malicious IPs: {malicious_count} ({malicious_score:.1f} points)")
            logger.info(f"  - Suspicious IPs: {suspicious_count} ({suspicious_score:.1f} points)")
            logger.info(f"  - Beacons detected: {beacons} ({beacon_score:.1f} points)")
            logger.info(f"  - C2 contacts: {c2_count} ({c2_score:.1f} points)")
            logger.info(f"  - Lateral movement: {lateral_movement_count} ({lateral_score:.1f} points)")
            
            return self.overall_score, self.severity
        
        except Exception as e:
            logger.error(f"Error calculating overall risk: {e}")
            return 0, 'UNKNOWN'
    
    def calculate_host_risk_scores(self) -> Dict[str, Dict]:
        """
        Calculate per-host risk scores
        
        Returns:
            Dictionary of host scores by IP
        """
        try:
            for result in self.enriched_results:
                ip = result.get('ip', 'unknown')
                classification = result.get('classification', 'UNKNOWN')
                
                # Base score from classification
                if classification == 'MALICIOUS':
                    score = 85
                elif classification == 'SUSPICIOUS':
                    score = 60
                elif classification == 'POLICY_VIOLATION':
                    score = 40
                else:
                    score = 20
                
                # Adjust by advanced analysis findings
                for beacon_ip in self.advanced_analysis.get('beaconing_analysis', {}).get('possible_beacons', {}):
                    if str(beacon_ip) == ip:
                        score = min(95, score + 15)
                
                for c2_ip in self.advanced_analysis.get('c2_indicators', {}).get('known_c2_contacts', {}):
                    if str(c2_ip) == ip:
                        score = min(95, score + 20)
                
                self.host_scores[ip] = {
                    'ip': ip,
                    'score': min(100, score),
                    'classification': classification,
                    'severity': self._score_to_severity(score)
                }
            
            return self.host_scores
        
        except Exception as e:
            logger.error(f"Error calculating host risk scores: {e}")
            return {}
    
    def get_risk_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive risk summary
        
        Returns:
            Dictionary with risk metrics and summaries
        """
        try:
            # Ensure scores are calculated
            if not self.host_scores:
                self.calculate_host_risk_scores()
            
            # Categorize hosts by risk
            critical_hosts = [h for h in self.host_scores.values() if h['severity'] == 'CRITICAL']
            high_risk_hosts = [h for h in self.host_scores.values() if h['severity'] == 'HIGH']
            medium_risk_hosts = [h for h in self.host_scores.values() if h['severity'] == 'MEDIUM']
            
            summary = {
                'overall_risk_score': self.overall_score,
                'overall_severity': self.severity,
                'critical_hosts': [h['ip'] for h in critical_hosts],
                'high_risk_hosts': [h['ip'] for h in high_risk_hosts],
                'medium_risk_hosts': [h['ip'] for h in medium_risk_hosts],
                'critical_host_count': len(critical_hosts),
                'high_risk_host_count': len(high_risk_hosts),
                'medium_risk_host_count': len(medium_risk_hosts),
                'total_hosts_analyzed': len(self.host_scores),
                'malicious_ips': len([r for r in self.enriched_results if r.get('classification') == 'MALICIOUS']),
                'suspicious_ips': len([r for r in self.enriched_results if r.get('classification') == 'SUSPICIOUS']),
                'host_scores': self.host_scores,
            }
            
            logger.info(f"Risk summary generated: {summary['critical_host_count']} critical, "
                       f"{summary['high_risk_host_count']} high-risk hosts")
            
            return summary
        
        except Exception as e:
            logger.error(f"Error generating risk summary: {e}")
            return {
                'overall_risk_score': 0,
                'overall_severity': 'UNKNOWN',
                'critical_hosts': [],
                'high_risk_hosts': [],
                'critical_host_count': 0,
                'high_risk_host_count': 0,
                'host_scores': {},
            }
    
    @staticmethod
    def _score_to_severity(score: int) -> str:
        """Convert numerical score to severity level"""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'
