"""
Rule-Based Intelligence Classification Module
Applies intelligent rules to classify IP addresses based on threat indicators
"""

import logging
from typing import Dict, Tuple

logger = logging.getLogger(__name__)


class RuleEngine:
    """Applies rule-based intelligence to classify IP addresses"""
    
    # Known IP ranges for CDNs and messaging services
    CLOUDFLARE_RANGES = [
        '104.16', '104.17', '104.18', '104.19', '104.20', '104.21',
        '104.22', '104.23', '104.24', '104.25', '104.26', '104.27',
        '104.28', '104.29', '104.30', '104.31', '141.101', '162.125',
        '162.158', '172.64', '172.65', '172.66', '172.67'
    ]
    
    TELEGRAM_RANGES = [
        '149.154', '149.155'
    ]
    
    GOOGLE_RANGES = [
        '8.8', '142.250', '142.251', '142.252', '142.253', '142.254',
        '172.217', '172.218', '172.219', '172.220', '172.221', '172.222',
        '172.223'
    ]
    
    AWS_RANGES = [
        '52.', '54.'
    ]
    
    MICROSOFT_RANGES = [
        '13.', '40.', '52.114', '52.115', '52.116', '52.117', '52.118'
    ]
    
    @staticmethod
    def _check_ip_in_range(ip: str, ranges: list) -> bool:
        """
        Check if IP belongs to any of the given ranges
        
        Args:
            ip: IP address to check
            ranges: List of IP range prefixes
            
        Returns:
            True if IP belongs to range, False otherwise
        """
        try:
            for ip_range in ranges:
                if ip.startswith(ip_range):
                    return True
        except (AttributeError, TypeError):
            logger.warning(f"Invalid IP format for range check: {ip}")
        
        return False
    
    @staticmethod
    def classify_ip(enriched_data: Dict) -> Tuple[str, str]:
        """
        Classify an IP address based on rule-based intelligence
        
        Args:
            enriched_data: Dictionary containing enriched IP data from APIs
            
        Returns:
            Tuple of (classification, reasoning)
        """
        # logger.info(f"Enriched data received for classification: {enriched_data}")
        ip = enriched_data.get('ip', '')
        vt_data = enriched_data.get('virustotal', {})
        abuse_data = enriched_data.get('abuseipdb', {})
        
        logger.debug(f"Classifying IP: {ip}")
        
        try:
            # Rule 1: Check if IP is in known benign CDN ranges
            if RuleEngine._check_ip_in_range(ip, RuleEngine.CLOUDFLARE_RANGES):
                return "NORMAL_TRAFFIC_CDN", "IP belongs to Cloudflare CDN range"
            
            if RuleEngine._check_ip_in_range(ip, RuleEngine.GOOGLE_RANGES):
                return "NORMAL_TRAFFIC_CDN", "IP belongs to Google infrastructure"
            
            if RuleEngine._check_ip_in_range(ip, RuleEngine.AWS_RANGES):
                return "NORMAL_TRAFFIC_CDN", "IP belongs to AWS infrastructure"
            
            if RuleEngine._check_ip_in_range(ip, RuleEngine.MICROSOFT_RANGES):
                return "NORMAL_TRAFFIC_CDN", "IP belongs to Microsoft infrastructure"
            
            # Rule 2: Check if IP belongs to Telegram (Policy Violation)
            if RuleEngine._check_ip_in_range(ip, RuleEngine.TELEGRAM_RANGES):
                return "POLICY_VIOLATION", "IP belongs to Telegram messaging service"
            
            # Get threat scores
            abuse_score = abuse_data.get('abuseConfidenceScore', 0)
            vt_malicious = vt_data.get('malicious', 0)
            vt_suspicious = vt_data.get('suspicious', 0)
            
            # Rule 3: Check AbuseIPDB score (high score = suspicious)
            if abuse_score > 75:
                return "MALICIOUS", f"AbuseIPDB confidence score: {abuse_score}% (Critical)"
            elif abuse_score > 50:
                return "SUSPICIOUS", f"AbuseIPDB confidence score: {abuse_score}%"
            
            # Rule 4: Check VirusTotal malicious detections
            if vt_malicious >= 10:
                return "MALICIOUS", f"VirusTotal malicious detections: {vt_malicious}"
            elif vt_malicious > 5:
                return "SUSPICIOUS", f"VirusTotal detections: {vt_malicious} malicious"
            
            # Rule 5: Check VirusTotal suspicious detections
            if vt_suspicious > 10:
                return "SUSPICIOUS", f"VirusTotal suspicious detections: {vt_suspicious}"
            
            # Rule 6: Check abuse reports
            if abuse_data.get('totalReports', 0) > 20:
                return "SUSPICIOUS", f"AbuseIPDB reports: {abuse_data.get('totalReports', 0)}"
            elif abuse_data.get('totalReports', 0) > 5:
                return "SUSPICIOUS", f"AbuseIPDB reports: {abuse_data.get('totalReports', 0)}"
            
            # Rule 7: Combined minor indicators
            combined_threat = vt_malicious + (vt_suspicious // 2)
            if combined_threat > 3:
                return "SUSPICIOUS", f"Combined threat indicators detected"
            
            # Default: Unknown (no significant threats detected)
            if vt_malicious == 0 and abuse_score == 0 and abuse_data.get('totalReports', 0) == 0:
                return "CLEAN", "No threat indicators detected"
            
            return "UNKNOWN", "Insufficient data for classification"
            
        except Exception as e:
            logger.error(f"Error classifying IP {ip}: {e}")
            return "ERROR", f"Classification error: {str(e)}"
    
    @staticmethod
    def get_risk_level(classification: str) -> int:
        """
        Get numerical risk level for a classification
        
        Args:
            classification: Classification string
            
        Returns:
            Risk level (0-10, where 10 is highest risk)
        """
        risk_map = {
            'CLEAN': 0,
            'NORMAL_TRAFFIC_CDN': 1,
            'UNKNOWN': 3,
            'POLICY_VIOLATION': 6,
            'SUSPICIOUS': 7,
            'MALICIOUS': 10,
            'ERROR': 5
        }
        
        return risk_map.get(classification, 5)
    
    @staticmethod
    def get_color_code(classification: str) -> str:
        """
        Get ANSI color code for classification display
        
        Args:
            classification: Classification string
            
        Returns:
            ANSI color code
        """
        color_map = {
            'CLEAN': '\033[92m',  # Green
            'NORMAL_TRAFFIC_CDN': '\033[94m',  # Blue
            'UNKNOWN': '\033[93m',  # Yellow
            'POLICY_VIOLATION': '\033[95m',  # Magenta
            'SUSPICIOUS': '\033[91m',  # Red
            'MALICIOUS': '\033[41m',  # Red background
            'ERROR': '\033[96m'  # Cyan
        }
        
        return color_map.get(classification, '\033[0m')  # Default: reset
