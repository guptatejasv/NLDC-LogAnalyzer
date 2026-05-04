"""
Output and Reporting Module
Generates human-readable reports of analysis results
"""

import logging
from typing import Dict, List
from datetime import datetime

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates analysis reports in multiple formats"""
    
    # ANSI color codes
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Color codes
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    
    # Background colors
    RED_BG = '\033[41m'
    GREEN_BG = '\033[42m'
    YELLOW_BG = '\033[43m'
    
    @staticmethod
    def _get_color_for_classification(classification: str) -> str:
        """Get color code for a classification"""
        color_map = {
            'CLEAN': ReportGenerator.GREEN,
            'NORMAL_TRAFFIC_CDN': ReportGenerator.BLUE,
            'UNKNOWN': ReportGenerator.YELLOW,
            'POLICY_VIOLATION': ReportGenerator.MAGENTA,
            'SUSPICIOUS': ReportGenerator.RED,
            'MALICIOUS': ReportGenerator.RED_BG,
            'ERROR': ReportGenerator.CYAN
        }
        return color_map.get(classification, ReportGenerator.RESET)
    
    @staticmethod
    def _get_threat_indicator(classification: str) -> str:
        """Get threat indicator symbol for a classification"""
        indicator_map = {
            'CLEAN': '✓',
            'NORMAL_TRAFFIC_CDN': '◆',
            'UNKNOWN': '?',
            'POLICY_VIOLATION': '⚠',
            'SUSPICIOUS': '⚡',
            'MALICIOUS': '✕',
            'ERROR': '!'
        }
        return indicator_map.get(classification, '?')
    
    @staticmethod
    def print_ip_summary(analysis_result: Dict):
        """
        Print a summary report for a single IP analysis
        
        Args:
            analysis_result: Dictionary containing analysis result
        """
        ip = analysis_result.get('ip', 'N/A')
        classification = analysis_result.get('classification', 'ERROR')
        reasoning = analysis_result.get('reasoning', 'No reason provided')
        
        vt_data = analysis_result.get('virustotal', {})
        abuse_data = analysis_result.get('abuseipdb', {})
        
        color = ReportGenerator._get_color_for_classification(classification)
        indicator = ReportGenerator._get_threat_indicator(classification)
        
        # Print header
        print(f"\n{ReportGenerator.BOLD}{'='*80}{ReportGenerator.RESET}")
        print(f"{color}{ReportGenerator.BOLD}{indicator} IP ANALYSIS: {ip}{ReportGenerator.RESET}")
        print(f"{ReportGenerator.BOLD}{'='*80}{ReportGenerator.RESET}")
        
        # Print classification
        print(f"\n{ReportGenerator.BOLD}Classification:{ReportGenerator.RESET} {color}{classification}{ReportGenerator.RESET}")
        print(f"{ReportGenerator.BOLD}Reasoning:{ReportGenerator.RESET} {reasoning}")
        
        # Print VirusTotal data
        if vt_data.get('status') == 'success':
            print(f"\n{ReportGenerator.BOLD}─ VirusTotal Analysis:{ReportGenerator.RESET}")
            print(f"  • Malicious detections:   {ReportGenerator.RED}{vt_data.get('malicious', 0)}{ReportGenerator.RESET}")
            print(f"  • Suspicious detections:  {ReportGenerator.YELLOW}{vt_data.get('suspicious', 0)}{ReportGenerator.RESET}")
            print(f"  • Harmless detections:    {ReportGenerator.GREEN}{vt_data.get('harmless', 0)}{ReportGenerator.RESET}")
            print(f"  • Undetected:             {vt_data.get('undetected', 0)}")
            print(f"  • Country:                {vt_data.get('country', 'Unknown')}")
            print(f"  • ASN:                    {vt_data.get('asn', 'Unknown')}")
        else:
            print(f"\n{ReportGenerator.BOLD}─ VirusTotal Analysis:{ReportGenerator.RESET} {ReportGenerator.YELLOW}No data available{ReportGenerator.RESET}")
        
        # Print AbuseIPDB data
        if abuse_data.get('status') == 'success':
            abuse_score = abuse_data.get('abuseConfidenceScore', 0)
            score_color = ReportGenerator.RED if abuse_score > 50 else (ReportGenerator.YELLOW if abuse_score > 25 else ReportGenerator.GREEN)
            
            print(f"\n{ReportGenerator.BOLD}─ AbuseIPDB Analysis:{ReportGenerator.RESET}")
            print(f"  • Confidence Score:       {score_color}{abuse_score}%{ReportGenerator.RESET}")
            print(f"  • Usage Type:             {abuse_data.get('usageType', 'Unknown')}")
            print(f"  • ISP:                    {abuse_data.get('isp', 'Unknown')}")
            print(f"  • Domain:                 {abuse_data.get('domain', 'Unknown')}")
            print(f"  • Total Reports:          {abuse_data.get('totalReports', 0)}")
            print(f"  • Last Reported:          {abuse_data.get('lastReportedAt', 'Never')}")
        else:
            print(f"\n{ReportGenerator.BOLD}─ AbuseIPDB Analysis:{ReportGenerator.RESET} {ReportGenerator.YELLOW}No data available{ReportGenerator.RESET}")
        
        print(f"\n{ReportGenerator.BOLD}{'='*80}{ReportGenerator.RESET}")
    
    @staticmethod
    def print_executive_summary(analysis_results: List[Dict]):
        """
        Print executive summary of all analysis results
        
        Args:
            analysis_results: List of analysis results
        """
        print(f"\n{ReportGenerator.BOLD}{ReportGenerator.UNDERLINE}EXECUTIVE SUMMARY{ReportGenerator.RESET}")
        print(f"{ReportGenerator.BOLD}{'─'*80}{ReportGenerator.RESET}")
        
        # Count classifications
        classifications = {}
        for result in analysis_results:
            classification = result.get('classification', 'UNKNOWN')
            classifications[classification] = classifications.get(classification, 0) + 1
        
        # Print counts
        print(f"\n{ReportGenerator.BOLD}Analysis Results:{ReportGenerator.RESET}")
        total_ips = len(analysis_results)
        print(f"Total IPs analyzed: {ReportGenerator.BOLD}{total_ips}{ReportGenerator.RESET}")
        
        for classification in sorted(classifications.keys()):
            count = classifications[classification]
            color = ReportGenerator._get_color_for_classification(classification)
            print(f"  • {color}{classification}{ReportGenerator.RESET}: {count} IP(s)")
        
        # Highlight threats
        threats = {k: v for k, v in classifications.items() if k in ['MALICIOUS', 'SUSPICIOUS', 'POLICY_VIOLATION']}
        if threats:
            print(f"\n{ReportGenerator.BOLD}{ReportGenerator.RED}⚠ THREAT SUMMARY:{ReportGenerator.RESET}")
            total_threats = sum(threats.values())
            print(f"Total threats detected: {ReportGenerator.RED}{ReportGenerator.BOLD}{total_threats}{ReportGenerator.RESET}")
            for threat_type, count in sorted(threats.items(), key=lambda x: x[1], reverse=True):
                color = ReportGenerator._get_color_for_classification(threat_type)
                print(f"  • {color}{threat_type}{ReportGenerator.RESET}: {count} IP(s)")
        else:
            print(f"\n{ReportGenerator.GREEN}✓ No threats detected{ReportGenerator.RESET}")
        
        print(f"\n{ReportGenerator.BOLD}{'─'*80}{ReportGenerator.RESET}")
    
    @staticmethod
    def print_detailed_report(analysis_results: List[Dict]):
        """
        Print detailed report for all analyzed IPs
        
        Args:
            analysis_results: List of analysis results
        """
        # Sort by classification (threats first)
        threat_order = {
            'MALICIOUS': 0,
            'SUSPICIOUS': 1,
            'POLICY_VIOLATION': 2,
            'UNKNOWN': 3,
            'ERROR': 4,
            'NORMAL_TRAFFIC_CDN': 5,
            'CLEAN': 6
        }
        
        sorted_results = sorted(
            analysis_results,
            key=lambda x: threat_order.get(x.get('classification', 'UNKNOWN'), 99)
        )
        
        # Print header
        print(f"\n{ReportGenerator.BOLD}{ReportGenerator.UNDERLINE}DETAILED IP ANALYSIS REPORT{ReportGenerator.RESET}")
        print(f"{ReportGenerator.BOLD}Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{ReportGenerator.RESET}")
        print(f"{ReportGenerator.BOLD}{'='*80}{ReportGenerator.RESET}\n")
        
        # Print each IP summary in table format
        print(f"{ReportGenerator.BOLD}{'IP Address':<20} {'Classification':<20} {'VT Malicious':<15} {'AbuseIPDB %':<15} {'Reasoning':<30}{ReportGenerator.RESET}")
        print(f"{ReportGenerator.BOLD}{'─'*100}{ReportGenerator.RESET}")
        
        for result in sorted_results:
            ip = result.get('ip', 'N/A')
            classification = result.get('classification', 'UNKNOWN')
            reasoning = result.get('reasoning', '')[:25]
            
            vt_data = result.get('virustotal', {})
            vt_malicious = vt_data.get('malicious', 0)
            
            abuse_data = result.get('abuseipdb', {})
            abuse_score = abuse_data.get('abuseConfidenceScore', 0)
            
            color = ReportGenerator._get_color_for_classification(classification)
            
            print(f"{ip:<20} {color}{classification:<20}{ReportGenerator.RESET} {vt_malicious:<15} {abuse_score:<15} {reasoning:<30}")
        
        print(f"{ReportGenerator.BOLD}{'='*100}{ReportGenerator.RESET}\n")
    
    @staticmethod
    def print_table_view(analysis_results: List[Dict]):
        """
        Print results in a clean table format
        
        Args:
            analysis_results: List of analysis results
        """
        print(f"\n{ReportGenerator.BOLD}{ReportGenerator.UNDERLINE}THREAT INTELLIGENCE REPORT{ReportGenerator.RESET}\n")
        
        # Table header
        print(f"{ReportGenerator.BOLD}{'IP Address':<20} {'Status':<20} {'Confidence':<12} {'Threats':<10}{ReportGenerator.RESET}")
        print(f"{ReportGenerator.BOLD}{'─'*70}{ReportGenerator.RESET}")
        
        for result in analysis_results:
            ip = result.get('ip', 'N/A')
            classification = result.get('classification', 'UNKNOWN')
            
            vt_data = result.get('virustotal', {})
            abuse_data = result.get('abuseipdb', {})
            
            abuse_score = abuse_data.get('abuseConfidenceScore', 0)
            vt_malicious = vt_data.get('malicious', 0)
            total_threats = vt_malicious + abuse_data.get('totalReports', 0)
            
            color = ReportGenerator._get_color_for_classification(classification)
            
            print(f"{ip:<20} {color}{classification:<20}{ReportGenerator.RESET} {abuse_score:>6}%        {total_threats:<10}")
        
        print(f"{ReportGenerator.BOLD}{'─'*70}{ReportGenerator.RESET}\n")
