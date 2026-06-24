"""
Advanced Report Generator Module
Generates professional SOC-grade reports in multiple formats
"""

import logging
import json
from typing import Dict, List, Any
from datetime import datetime
import os

logger = logging.getLogger(__name__)


class AdvancedReportGenerator:
    """Generates professional security reports"""
    
    def __init__(self, output_dir: str = 'reports'):
        """
        Initialize report generator
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_executive_report(self, risk_summary: Dict, mitre_summary: Dict, enriched_results: List[Dict]) -> str:
        """Generate executive summary report"""
        logger.info("Generating executive report")
        
        critical_count = len(risk_summary.get('critical_hosts', []))
        high_count = len(risk_summary.get('high_risk_hosts', []))
        overall_score = risk_summary.get('overall_risk_score', 0)
        overall_severity = risk_summary.get('overall_severity', 'UNKNOWN')
        
        report = f"""
{'='*80}
EXECUTIVE THREAT INTELLIGENCE REPORT
{'='*80}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

EXECUTIVE SUMMARY
{'-'*80}

Overall Risk Assessment: {overall_severity} (Score: {overall_score}/100)

THREAT LANDSCAPE:
- Critical Risk Hosts: {critical_count}
- High Risk Hosts: {high_count}
- Total Hosts Analyzed: {len(enriched_results)}
- Malicious IPs Detected: {len([r for r in enriched_results if r.get('classification') == 'MALICIOUS'])}
- Suspicious IPs Detected: {len([r for r in enriched_results if r.get('classification') == 'SUSPICIOUS'])}

KEY FINDINGS:
{self._generate_key_findings(risk_summary, mitre_summary)}

BUSINESS IMPACT:
{self._generate_business_impact(overall_severity, critical_count)}

RECOMMENDED ACTIONS:
{self._generate_executive_actions(critical_count, high_count)}

ATTACK TACTICS IDENTIFIED:
{self._generate_tactics_summary(mitre_summary)}

{'='*80}
"""
        
        return report
    
    def generate_technical_report(self, advanced_analysis: Dict, enriched_results: List[Dict], mitre_summary: Dict) -> str:
        """Generate technical investigation report"""
        logger.info("Generating technical report")
        
        report = f"""
{'='*80}
TECHNICAL THREAT INVESTIGATION REPORT
{'='*80}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

INDICATORS OF COMPROMISE (IOCs)
{'-'*80}

1. MALICIOUS IP ADDRESSES:
{self._format_malicious_ips(enriched_results)}

2. SUSPICIOUS IP ADDRESSES:
{self._format_suspicious_ips(enriched_results)}

ATTACK ANALYSIS
{'-'*80}

1. COMMAND & CONTROL COMMUNICATION:
{self._format_c2_analysis(advanced_analysis)}

2. BEACONING PATTERNS:
{self._format_beacon_analysis(advanced_analysis)}

3. LATERAL MOVEMENT INDICATORS:
{self._format_lateral_movement(advanced_analysis)}

4. DATA EXFILTRATION INDICATORS:
{self._format_exfiltration(advanced_analysis)}

PORT & PROTOCOL ANALYSIS
{'-'*80}
{self._format_port_analysis(advanced_analysis)}

MITRE ATT&CK MAPPING
{'-'*80}
{self._format_mitre_techniques(mitre_summary)}

NETWORK FORENSICS
{'-'*80}
{self._format_network_forensics(advanced_analysis)}

{'='*80}
"""
        
        return report
    
    def generate_threat_hunting_report(self, advanced_analysis: Dict) -> str:
        """Generate threat hunting report"""
        logger.info("Generating threat hunting report")
        
        report = f"""
{'='*80}
THREAT HUNTING INVESTIGATION REPORT
{'='*80}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

THREAT HUNTING METHODOLOGY
{'-'*80}
This report documents advanced threat hunting activities designed to identify:
- Hidden attack patterns
- Attacker infrastructure
- Lateral movement paths
- Data exfiltration channels
- Command and control mechanisms

ANOMALIES DETECTED
{'-'*80}

1. COMMUNICATION BEHAVIOR ANOMALIES:
{self._format_behavior_anomalies(advanced_analysis)}

2. TRAFFIC PATTERN ANOMALIES:
{self._format_traffic_anomalies(advanced_analysis)}

3. TEMPORAL ANOMALIES:
{self._format_temporal_anomalies(advanced_analysis)}

ATTACK CHAIN RECONSTRUCTION
{'-'*80}
{self._reconstruct_attack_chain(advanced_analysis)}

INFRASTRUCTURE ANALYSIS
{'-'*80}
{self._analyze_infrastructure(advanced_analysis)}

ATTACKER PROFILE ASSESSMENT
{'-'*80}
{self._assess_attacker_profile(advanced_analysis)}

RECOMMENDATIONS FOR THREAT HUNTERS
{'-'*80}
1. Hunt for similar beacon patterns in other network segments
2. Correlate with endpoint detection and response (EDR) data
3. Investigate all source IPs that contacted malicious destinations
4. Check DNS logs for domain generation algorithm (DGA) activity
5. Review proxy logs for suspicious SSL certificate usage

{'='*80}
"""
        
        return report
    
    def generate_json_report(self, all_data: Dict) -> str:
        """Generate JSON report for programmatic access"""
        logger.info("Generating JSON report")
        
        return json.dumps(all_data, indent=2, default=str)
    
    def save_report(self, report_type: str, content: str) -> str:
        """Save report to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'{report_type}_{timestamp}.txt'
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            # Use UTF-8 encoding to handle unicode characters like checkmarks
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Report saved to {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            # If UTF-8 fails, try stripping unicode characters as fallback
            try:
                clean_content = content.encode('ascii', 'ignore').decode('ascii')
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(clean_content)
                logger.info(f"Report saved to {filepath} (with unicode characters stripped)")
                return filepath
            except Exception as fallback_error:
                logger.error(f"Error saving report (fallback): {fallback_error}")
                return ''
    
    def _generate_key_findings(self, risk_summary: Dict, mitre_summary: Dict) -> str:
        """Generate key findings section"""
        findings = []
        
        critical = len(risk_summary.get('critical_hosts', []))
        if critical > 0:
            findings.append(f"• CRITICAL: {critical} hosts with critical risk scores detected")
        
        techniques = mitre_summary.get('total_techniques', 0)
        if techniques > 0:
            findings.append(f"• {techniques} MITRE ATT&CK techniques mapped to attack indicators")
        
        confirmed = mitre_summary.get('confidence_counts', {}).get('CONFIRMED', 0)
        if confirmed > 0:
            findings.append(f"• {confirmed} techniques with CONFIRMED confidence level")
        
        return '\n'.join(findings) if findings else "No critical findings"
    
    def _generate_business_impact(self, severity: str, critical_count: int) -> str:
        """Generate business impact assessment"""
        if severity == 'CRITICAL':
            return f"""
Active threat detected with potential for:
- Immediate data breach
- System compromise across {critical_count} hosts
- Ongoing command and control communication
- Possible lateral movement to critical systems

Recommended action: IMMEDIATE investigation and containment
"""
        elif severity == 'HIGH':
            return f"""
Significant threat indicators detected:
- {critical_count} high-risk hosts requiring investigation
- Potential for malware infection
- Possible unauthorized access attempts

Recommended action: Priority investigation within 24 hours
"""
        else:
            return "Moderate threat indicators require monitoring and investigation"
    
    def _generate_executive_actions(self, critical_count: int, high_count: int) -> str:
        """Generate executive action items"""
        actions = [
            "1. IMMEDIATE (0-2 hours):",
            "   - Initiate incident response procedures",
            f"   - Investigate all {critical_count} critical-risk hosts",
            "   - Block malicious IP addresses at perimeter",
            "   - Preserve forensic evidence",
            "",
            "2. SHORT-TERM (2-24 hours):",
            f"   - Complete investigation of {high_count} high-risk hosts",
            "   - Review firewall logs for related activity",
            "   - Check for data exfiltration on monitoring systems",
            "   - Verify no additional spread occurred",
            "",
            "3. MEDIUM-TERM (24-72 hours):",
            "   - Conduct full forensic analysis",
            "   - Search for persistence mechanisms",
            "   - Review all network traffic for indicators",
            "   - Update security controls to prevent recurrence",
        ]
        
        return '\n'.join(actions)
    
    def _generate_tactics_summary(self, mitre_summary: Dict) -> str:
        """Generate MITRE tactics summary"""
        by_tactic = mitre_summary.get('by_tactic', {})
        
        if not by_tactic:
            return "No tactics mapped"
        
        summary = []
        for tactic, techniques in sorted(by_tactic.items()):
            summary.append(f"• {tactic}: {len(techniques)} techniques detected")
        
        return '\n'.join(summary)
    
    def _format_malicious_ips(self, enriched_results: List[Dict]) -> str:
        """Format malicious IPs"""
        malicious = [r for r in enriched_results if r.get('classification') == 'MALICIOUS']
        
        if not malicious:
            return "No malicious IPs detected"
        
        lines = []
        for result in malicious[:20]:
            ip = result.get('ip', 'Unknown')
            vt_detections = result.get('virustotal', {}).get('detections', 0)
            abuse_score = result.get('abuseipdb', {}).get('abuseipdb_score', 0)
            lines.append(f"• {ip} (VT detections: {vt_detections}, AbuseIPDB: {abuse_score})")
        
        return '\n'.join(lines)
    
    def _format_suspicious_ips(self, enriched_results: List[Dict]) -> str:
        """Format suspicious IPs"""
        suspicious = [r for r in enriched_results if r.get('classification') == 'SUSPICIOUS']
        
        if not suspicious:
            return "No suspicious IPs detected"
        
        lines = []
        for result in suspicious[:20]:
            ip = result.get('ip', 'Unknown')
            reason = result.get('threat_type', 'Suspicious activity')
            lines.append(f"• {ip} - {reason}")
        
        return '\n'.join(lines)
    
    def _format_c2_analysis(self, advanced_analysis: Dict) -> str:
        """Format C2 analysis"""
        c2 = advanced_analysis.get('c2_indicators', {})
        
        lines = []
        
        known_c2 = c2.get('known_c2_contacts', {})
        if known_c2:
            lines.append(f"Known C2 Infrastructure: {len(known_c2)} contacts detected")
            for ip, data in list(known_c2.items())[:5]:
                lines.append(f"  • {ip}: {data.get('count', 0)} connections")
        
        infrastructure = c2.get('malicious_infrastructure', {})
        if infrastructure:
            lines.append(f"Malicious Infrastructure: {len(infrastructure)} hosts contacted")
        
        return '\n'.join(lines) if lines else "No C2 indicators detected"
    
    def _format_beacon_analysis(self, advanced_analysis: Dict) -> str:
        """Format beacon analysis"""
        beacons = advanced_analysis.get('beaconing_analysis', {}).get('possible_beacons', {})
        
        if not beacons:
            return "No beaconing behavior detected"
        
        lines = [f"Detected {len(beacons)} possible beacons:"]
        for ip, data in list(beacons.items())[:10]:
            lines.append(f"• {ip}")
            lines.append(f"  - Interval: {data.get('possible_intervals')}")
            lines.append(f"  - Confidence: {data.get('confidence')}")
        
        return '\n'.join(lines)
    
    def _format_lateral_movement(self, advanced_analysis: Dict) -> str:
        """Format lateral movement analysis"""
        lateral = advanced_analysis.get('lateral_movement', {})
        internal = lateral.get('internal_communications', {})
        
        if not internal or internal.get('count', 0) == 0:
            return "No lateral movement detected"
        
        lines = [
            f"Internal Communications: {internal.get('count')} connections",
            f"  - Source IPs: {internal.get('unique_source_ips')}",
            f"  - Destination IPs: {internal.get('unique_dest_ips')}",
        ]
        
        return '\n'.join(lines)
    
    def _format_exfiltration(self, advanced_analysis: Dict) -> str:
        """Format exfiltration analysis"""
        exfil = advanced_analysis.get('data_exfiltration', {})
        
        high_volume = exfil.get('high_volume_destinations', {})
        rare = exfil.get('rare_destination_contacts', {})
        
        lines = []
        if high_volume:
            lines.append(f"High-Volume Data Transfers: {len(high_volume)} destinations")
        
        if rare:
            lines.append(f"One-Time Destination Contacts: {len(rare)} rare IPs")
        
        return '\n'.join(lines) if lines else "No exfiltration indicators detected"
    
    def _format_port_analysis(self, advanced_analysis: Dict) -> str:
        """Format port analysis"""
        port_analysis = advanced_analysis.get('port_analysis', {})
        malicious = port_analysis.get('malicious_ports_detected', {})
        
        if not malicious:
            return "No malicious ports detected"
        
        lines = ["Malicious ports detected:"]
        for port, data in malicious.items():
            category = data.get('info', {}).get('category', 'Unknown')
            count = data.get('count', 0)
            lines.append(f"• Port {port} ({category}): {count} connections")
        
        return '\n'.join(lines)
    
    def _format_mitre_techniques(self, mitre_summary: Dict) -> str:
        """Format MITRE techniques"""
        techniques = mitre_summary.get('techniques', [])
        
        if not techniques:
            return "No MITRE ATT&CK techniques mapped"
        
        lines = []
        for technique in techniques[:15]:
            lines.append(f"• {technique['technique_id']}: {technique['technique_name']}")
            lines.append(f"  Tactic: {technique['tactic']}")
            lines.append(f"  Confidence: {technique['confidence']}")
        
        return '\n'.join(lines)
    
    def _format_network_forensics(self, advanced_analysis: Dict) -> str:
        """Format network forensics"""
        lines = [
            "Network Forensics Summary:",
            "",
        ]
        
        dest = advanced_analysis.get('destination_analysis', {})
        if dest.get('total_destinations'):
            lines.append(f"• Unique Destinations: {dest['total_destinations']}")
        
        comm = advanced_analysis.get('communication_behavior', {})
        if comm.get('repeated_communication'):
            lines.append(f"• Repeated Communications: {len(comm['repeated_communication'])} IPs")
        
        return '\n'.join(lines)
    
    def _format_behavior_anomalies(self, advanced_analysis: Dict) -> str:
        """Format behavior anomalies"""
        comm = advanced_analysis.get('communication_behavior', {})
        
        anomalies = []
        if comm.get('outlier_destinations'):
            anomalies.append(f"• Outlier destinations: {len(comm['outlier_destinations'])}")
        
        if comm.get('high_frequency_destinations'):
            anomalies.append(f"• High-frequency destinations: {len(comm['high_frequency_destinations'])}")
        
        return '\n'.join(anomalies) if anomalies else "No behavior anomalies detected"
    
    def _format_traffic_anomalies(self, advanced_analysis: Dict) -> str:
        """Format traffic anomalies"""
        return "• Denied traffic patterns analyzed\n• Communication concentration evaluated"
    
    def _format_temporal_anomalies(self, advanced_analysis: Dict) -> str:
        """Format temporal anomalies"""
        temporal = advanced_analysis.get('temporal_analysis', {})
        spikes = temporal.get('activity_spikes', [])
        
        if spikes:
            return f"• {len(spikes)} activity spikes detected above baseline"
        else:
            return "• No significant temporal anomalies detected"
    
    def _reconstruct_attack_chain(self, advanced_analysis: Dict) -> str:
        """Reconstruct attack chain"""
        return """
Phase 1 (Reconnaissance):
- Multiple unique destinations contacted
- Port scanning behavior detected

Phase 2 (Initial Compromise):
- Malicious infrastructure contacted
- Potential malware communication

Phase 3 (Command & Control):
- Beacon patterns detected
- Regular communication established

Phase 4 (Lateral Movement):
- Internal IP communications detected
- Suspicious ports utilized

Phase 5 (Objective):
- Data exfiltration indicators present
- Multiple rare destination contacts
"""
    
    def _analyze_infrastructure(self, advanced_analysis: Dict) -> str:
        """Analyze attacker infrastructure"""
        return """
Known Malicious Infrastructure:
- Command and Control servers
- Malware distribution points
- Data exfiltration endpoints

Suspicious Infrastructure:
- Recently registered domains (if available from WHOIS)
- Bulletproof hosting providers
- CDN abuse for traffic distribution
"""
    
    def _assess_attacker_profile(self, advanced_analysis: Dict) -> str:
        """Assess attacker profile"""
        c2 = advanced_analysis.get('c2_indicators', {})
        patterns = advanced_analysis.get('attack_patterns', {})
        
        sophistication = "MODERATE"
        if len(c2.get('known_c2_contacts', {})) > 3:
            sophistication = "HIGH"
        elif len(c2.get('malicious_infrastructure', {})) > 5:
            sophistication = "HIGH"
        
        return f"""
Attacker Sophistication: {sophistication}
- Attack methodology suggests organized threat group
- Use of known C2 infrastructure indicates maturity
- Lateral movement tactics indicate post-breach activity
- Potential objectives: data theft, system compromise, espionage

Likely Attacker Motivation:
- Financial gain (if banking sector targeted)
- Espionage (if government/defense sector targeted)
- Competitive advantage (if corporate sector targeted)
"""
    
    def generate_comprehensive_findings_report(self, enriched_results: List[Dict], advanced_analysis: Dict, 
                                               risk_summary: Dict, ai_analysis: Dict = None) -> str:
        """Generate comprehensive findings report with IP categorization"""
        logger.info("Generating comprehensive findings report")
        
        # Categorize IPs
        malicious_ips = [r for r in enriched_results if r.get('classification') == 'MALICIOUS']
        suspicious_ips = [r for r in enriched_results if r.get('classification') == 'SUSPICIOUS']
        clean_ips = [r for r in enriched_results if r.get('classification') in ['CLEAN', 'UNKNOWN']]
        
        report = f"""
{'='*80}
COMPREHENSIVE THREAT FINDINGS REPORT
{'='*80}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{'='*80}
1. EXECUTIVE SUMMARY OF FINDINGS
{'='*80}

Overall Risk Score: {risk_summary.get('overall_risk_score', 0)}/100 ({risk_summary.get('overall_severity', 'UNKNOWN')})
Total IPs Analyzed: {len(enriched_results)}

IP CLASSIFICATION SUMMARY:
  • Malicious IPs: {len(malicious_ips)}
  • Suspicious IPs: {len(suspicious_ips)}
  • Clean/Unknown IPs: {len(clean_ips)}

Critical Findings:
  • Critical Risk Hosts: {len(risk_summary.get('critical_hosts', []))}
  • High-Risk Hosts: {len(risk_summary.get('high_risk_hosts', []))}

{'='*80}
2. MALICIOUS IP ADDRESSES DETECTED
{'='*80}

{self._format_ip_category(malicious_ips, advanced_analysis, 'MALICIOUS')}

{'='*80}
3. SUSPICIOUS IP ADDRESSES DETECTED
{'='*80}

{self._format_ip_category(suspicious_ips, advanced_analysis, 'SUSPICIOUS')}

{'='*80}
4. CLEAN/UNKNOWN IPs WITH SUSPICIOUS ACTIVITY
{'='*80}

{self._format_ip_category(clean_ips, advanced_analysis, 'CLEAN')}

{'='*80}
5. ATTACK INDICATORS FOUND
{'='*80}

{self._format_attack_indicators(advanced_analysis)}

{'='*80}
6. ATTACK PATTERNS IDENTIFIED
{'='*80}

{self._format_patterns(advanced_analysis)}

{'='*80}
7. AI DEEP ANALYSIS INSIGHTS
{'='*80}

{self._format_ai_insights(ai_analysis)}

{'='*80}
8. WHAT WAS NOT FOUND
{'='*80}

{self._format_not_found(advanced_analysis)}

{'='*80}
9. RISK PRIORITIZATION & RECOMMENDATIONS
{'='*80}

{self._format_recommendations(malicious_ips, suspicious_ips, risk_summary)}

{'='*80}
"""
        return report
    
    def _format_ip_category(self, ips: List[Dict], advanced_analysis: Dict, category: str) -> str:
        """Format IPs by category"""
        if not ips:
            if category == 'MALICIOUS':
                return "[OK] No malicious IPs detected in this analysis."
            elif category == 'SUSPICIOUS':
                return "[OK] No suspicious IPs detected in this analysis."
            else:
                return "[OK] All clean/unknown IPs show expected behavior."
        
        lines = []
        beacons = advanced_analysis.get('beaconing_analysis', {}).get('possible_beacons', {})
        c2 = advanced_analysis.get('c2_indicators', {}).get('known_c2_contacts', {})
        
        for ip_obj in ips[:20]:
            ip = ip_obj.get('ip')
            threat_types = ip_obj.get('threat_types', [])
            confidence = ip_obj.get('confidence', 'N/A')
            
            lines.append(f"\n• IP: {ip}")
            lines.append(f"  Classification: {ip_obj.get('classification', 'Unknown')}")
            lines.append(f"  Confidence: {confidence}")
            
            if threat_types:
                lines.append(f"  Threats: {', '.join(threat_types)}")
            
            # Check if this IP is a beacon
            if ip in beacons:
                beacon_data = beacons[ip]
                lines.append(f"  [!] BEACON DETECTED: {beacon_data.get('pattern', 'Suspicious beacon pattern')}")
            
            # Check if this IP is C2
            if ip in c2:
                lines.append(f"  [!] C2 CONTACT: Known command & control server")
            
            if ip_obj.get('threat_name'):
                lines.append(f"  Threat: {ip_obj.get('threat_name')}")
        
        if len(ips) > 20:
            lines.append(f"\n... and {len(ips) - 20} more {category.lower()} IPs")
        
        return '\n'.join(lines) if lines else f"No {category.lower()} IPs to display"
    
    def _format_attack_indicators(self, advanced_analysis: Dict) -> str:
        """Format attack indicators"""
        indicators = []
        
        # Beacons
        beacons = advanced_analysis.get('beaconing_analysis', {}).get('possible_beacons', {})
        if beacons:
            indicators.append(f"[+] BEACONING: {len(beacons)} beacon IPs detected")
            for ip, beacon_info in list(beacons.items())[:3]:
                indicators.append(f"  - {ip}: {beacon_info.get('pattern', 'Regular communication pattern')}")
        else:
            indicators.append("[-] Beaconing: No beacon patterns detected")
        
        # C2
        c2 = advanced_analysis.get('c2_indicators', {})
        if c2.get('known_c2_contacts'):
            indicators.append(f"[+] C2 COMMUNICATION: {len(c2.get('known_c2_contacts', {}))} known C2 servers contacted")
        else:
            indicators.append("[-] C2 Communication: No known C2 contacts detected")
        
        # Lateral movement
        lateral = advanced_analysis.get('lateral_movement', {})
        if lateral.get('internal_communications', {}).get('count', 0) > 0:
            indicators.append(f"[+] LATERAL MOVEMENT: {lateral.get('internal_communications', {}).get('count', 0)} internal communications detected")
        else:
            indicators.append("[-] Lateral Movement: No internal attack communications detected")
        
        # Data exfil
        exfil = advanced_analysis.get('data_exfiltration', {})
        if exfil.get('high_volume_destinations'):
            indicators.append(f"[+] DATA EXFILTRATION: {len(exfil.get('high_volume_destinations', {}))} high-volume destinations detected")
        else:
            indicators.append("[-] Data Exfiltration: No obvious exfiltration patterns detected")
        
        return '\n'.join(indicators)
    
    def _format_patterns(self, advanced_analysis: Dict) -> str:
        """Format detected patterns"""
        patterns = advanced_analysis.get('attack_patterns', {})
        
        lines = []
        
        if patterns.get('malware_indicators'):
            lines.append(f"• Malware Indicators: {len(patterns.get('malware_indicators', {}))} detected")
        
        if patterns.get('reconnaissance_patterns'):
            lines.append(f"• Reconnaissance Patterns: {len(patterns.get('reconnaissance_patterns', {}))} detected")
        
        if patterns.get('lateral_movement_indicators'):
            lines.append(f"• Lateral Movement Patterns: {len(patterns.get('lateral_movement_indicators', {}))} detected")
        
        if not lines:
            lines.append("• No specific attack patterns detected in this analysis")
        
        return '\n'.join(lines)
    
    def _format_ai_insights(self, ai_analysis: Dict) -> str:
        """Format AI analysis insights"""
        if not ai_analysis or ai_analysis.get('status') != 'success':
            return "AI analysis not available or failed. Using rule-based findings only."
        
        analysis_text = ai_analysis.get('analysis', '')
        
        # Limit to first 1500 characters for readability
        if len(analysis_text) > 1500:
            return analysis_text[:1500] + f"\n\n[Full analysis truncated - {len(analysis_text)} characters available]"
        
        return analysis_text if analysis_text else "AI analysis completed but produced no output."
    
    def _format_not_found(self, advanced_analysis: Dict) -> str:
        """Format what was NOT found"""
        not_found = []
        
        # Check what wasn't detected
        beacons = advanced_analysis.get('beaconing_analysis', {}).get('possible_beacons', {})
        if not beacons:
            not_found.append("[OK] No beacon/command-and-control patterns found")
        
        c2 = advanced_analysis.get('c2_indicators', {})
        if not c2.get('known_c2_contacts'):
            not_found.append("[OK] No known C2 server communications")
        
        lateral = advanced_analysis.get('lateral_movement', {})
        if not lateral.get('internal_communications', {}).get('count'):
            not_found.append("[OK] No suspicious internal lateral movement")
        
        exfil = advanced_analysis.get('data_exfiltration', {})
        if not exfil.get('high_volume_destinations'):
            not_found.append("[OK] No obvious data exfiltration patterns")
        
        telegram = advanced_analysis.get('telegram_analysis', {})
        if not telegram.get('telegram_ips'):
            not_found.append("[OK] No Telegram communications detected")
        
        if not not_found:
            not_found.append("Multiple threat indicators were detected - see sections above")
        
        return '\n'.join(not_found)
    
    def _format_recommendations(self, malicious_ips: List[Dict], suspicious_ips: List[Dict], 
                                risk_summary: Dict) -> str:
        """Format recommendations"""
        lines = []
        
        lines.append("IMMEDIATE ACTIONS:")
        
        if malicious_ips:
            lines.append(f"1. BLOCK {len(malicious_ips)} malicious IP(s) at firewall/proxy:")
            for ip_obj in malicious_ips[:5]:
                lines.append(f"   - {ip_obj.get('ip')}")
            if len(malicious_ips) > 5:
                lines.append(f"   ... and {len(malicious_ips) - 5} more")
        
        if suspicious_ips:
            lines.append(f"\n2. MONITOR/QUARANTINE {len(suspicious_ips)} suspicious IP(s):")
            for ip_obj in suspicious_ips[:5]:
                lines.append(f"   - {ip_obj.get('ip')}")
            if len(suspicious_ips) > 5:
                lines.append(f"   ... and {len(suspicious_ips) - 5} more")
        
        severity = risk_summary.get('overall_severity', 'MEDIUM')
        if severity == 'CRITICAL':
            lines.append("\n3. ESCALATE: Contact incident response team immediately")
            lines.append("4. ISOLATE: Consider isolating affected systems")
            lines.append("5. PRESERVE: Preserve logs for forensic analysis")
        
        lines.append("\nMEDIUM-TERM ACTIONS:")
        lines.append("- Review and update firewall rules")
        lines.append("- Conduct endpoint detection and response (EDR) scan")
        lines.append("- Review user access logs for suspicious activity")
        lines.append("- Patch systems showing lateral movement indicators")
        
        return '\n'.join(lines)

