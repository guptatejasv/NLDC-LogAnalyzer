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
    PURPLE = '\033[35m'
    
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
    
    @staticmethod
    def print_communication_analysis(comm_analysis: Dict, df):
        """
        Print detailed communication type analysis
        
        Args:
            comm_analysis: Dictionary containing communication analysis results
            df: DataFrame containing the parsed logs
        """
        print(f"\n{ReportGenerator.BOLD}{ReportGenerator.UNDERLINE}{'='*80}")
        print(f"DETAILED COMMUNICATION ANALYSIS REPORT")
        print(f"{'='*80}{ReportGenerator.RESET}\n")
        
        # Overall communication counts
        overall_counts = comm_analysis.get('overall_communication_counts', {})
        if overall_counts:
            print(f"{ReportGenerator.BOLD}{ReportGenerator.BLUE}1. OVERALL COMMUNICATION BREAKDOWN{ReportGenerator.RESET}")
            print(f"{ReportGenerator.BOLD}─{ReportGenerator.RESET}" * 40)
            for comm_type, count in sorted(overall_counts.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(df)) * 100 if len(df) > 0 else 0
                bar_length = int(percentage / 5)
                bar = "█" * bar_length
                print(f"  {comm_type:<40} {count:>4} ({percentage:>5.1f}%) {bar}")
            print()
        
        # Top 5 communication types
        top_5 = comm_analysis.get('top_5_communication_types', {})
        if top_5:
            print(f"{ReportGenerator.BOLD}{ReportGenerator.CYAN}2. TOP 5 COMMUNICATION TYPES{ReportGenerator.RESET}")
            print(f"{ReportGenerator.BOLD}─{ReportGenerator.RESET}" * 40)
            for idx, (comm_type, count) in enumerate(top_5.items(), 1):
                percentage = (count / len(df)) * 100 if len(df) > 0 else 0
                print(f"  #{idx} {comm_type:<38} {count:>4} ({percentage:>5.1f}%)")
            print()
        
        # Communication by action
        comm_by_action = comm_analysis.get('communication_by_action', {})
        if comm_by_action:
            print(f"{ReportGenerator.BOLD}{ReportGenerator.MAGENTA}3. COMMUNICATION BY ACTION STATUS{ReportGenerator.RESET}")
            print(f"{ReportGenerator.BOLD}─{ReportGenerator.RESET}" * 40)
            for comm_type in sorted(comm_by_action.keys()):
                actions = comm_by_action[comm_type]
                print(f"  {ReportGenerator.BOLD}{comm_type}{ReportGenerator.RESET}")
                for action, count in actions.items():
                    action_color = ReportGenerator.GREEN if action.lower() in ['allow', 'accept'] else ReportGenerator.RED
                    print(f"    • {action_color}{action}{ReportGenerator.RESET}: {count}")
            print()
        
        # Summary statistics
        total_unique = comm_analysis.get('total_unique_communication_types', 0)
        total_records = len(df)
        print(f"{ReportGenerator.BOLD}{ReportGenerator.YELLOW}4. SUMMARY STATISTICS{ReportGenerator.RESET}")
        print(f"{ReportGenerator.BOLD}─{ReportGenerator.RESET}" * 40)
        print(f"  • Total unique communication types: {ReportGenerator.BOLD}{total_unique}{ReportGenerator.RESET}")
        print(f"  • Total log records analyzed:       {ReportGenerator.BOLD}{total_records}{ReportGenerator.RESET}")
        if total_unique > 0:
            avg_per_type = total_records / total_unique
            print(f"  • Average records per type:        {ReportGenerator.BOLD}{avg_per_type:.2f}{ReportGenerator.RESET}")
        print()
        
        print(f"{ReportGenerator.BOLD}{'='*80}{ReportGenerator.RESET}\n")
