"""
Integrated Threat Hunting Main Module
Orchestrates complete SOC-grade threat hunting analysis pipeline
"""

import sys
import logging
from pathlib import Path

# Add project root and src directory to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / 'src'))

from src.logger_setup import setup_logger
from src.parser import LogParser
from src.enrich import IPEnricher
from src.rules import RuleEngine
from src.advanced_analyzer import AdvancedAnalyzer
from src.risk_engine import RiskScoringEngine
from src.mitre_mapper import MITREMapper
from src.time_analyzer import TimeBasedAnalyzer
from src.ai_analyzer import AIThreatAnalyzer
from src.report_generator_advanced import AdvancedReportGenerator
from config.config import Config

# Setup logger
logger = setup_logger(__name__)


class IntegratedThreatHunter:
    """Integrated threat hunting and forensics platform"""
    
    def __init__(self, csv_path: str, ai_provider: str = 'ollama', ai_key: str = None):
        """
        Initialize threat hunter
        
        Args:
            csv_path: Path to CSV log file
            ai_provider: 'ollama' (local DeepSeek)
            ai_key: Not used (for backward compatibility)
        """
        self.csv_path = csv_path
        self.ai_provider = ai_provider
        self.ai_key = ai_key
        self.config = Config()
        self.results = {}
        
        logger.info("="*80)
        logger.info("Integrated Threat Hunter - Starting Analysis")
        logger.info("="*80)
    
    def run_complete_analysis(self):
        """Execute complete threat hunting pipeline"""
        try:
            # Step 1: Parse logs
            logger.info("\n[STEP 1/7] Parsing network logs...")
            parsed_data = self._parse_logs()
            
            # Step 2: Enrich IPs
            logger.info("\n[STEP 2/7] Enriching IPs with threat intelligence...")
            enriched_results = self._enrich_ips(parsed_data)
            
            # Step 3: Advanced Analysis
            logger.info("\n[STEP 3/7] Running advanced threat hunting analysis...")
            advanced_analysis = self._run_advanced_analysis(parsed_data, enriched_results)
            
            # Step 4: Time-based Analysis
            logger.info("\n[STEP 4/7] Analyzing temporal patterns...")
            temporal_analysis = self._run_temporal_analysis(parsed_data)
            
            # Step 5: Risk Scoring
            logger.info("\n[STEP 5/7] Calculating risk scores...")
            risk_summary = self._calculate_risk_scores(enriched_results, advanced_analysis)
            
            # Step 6: MITRE Mapping
            logger.info("\n[STEP 6/7] Mapping to MITRE ATT&CK framework...")
            mitre_summary = self._map_mitre(advanced_analysis, enriched_results)
            
            # Step 7: Generate Reports
            logger.info("\n[STEP 7/7] Generating professional reports...")
            
            # Generate reports (we'll add AI analysis after if available)
            reports = self._generate_reports(enriched_results, advanced_analysis, risk_summary, mitre_summary)
            
            # Optional: AI Analysis
            if self.ai_provider and self.ai_provider != 'none':
                logger.info("\n[BONUS] Running AI threat analysis...")
                ai_analysis = self._run_ai_analysis(enriched_results, advanced_analysis, risk_summary, parsed_data)
                
                # Regenerate reports with AI analysis included
                if ai_analysis.get('status') == 'success':
                    reports = self._generate_reports(enriched_results, advanced_analysis, risk_summary, mitre_summary, ai_analysis)
            else:
                ai_analysis = None
            
            self.results = {
                'parsed_data': parsed_data,
                'enriched_results': enriched_results,
                'advanced_analysis': advanced_analysis,
                'temporal_analysis': temporal_analysis,
                'risk_summary': risk_summary,
                'mitre_summary': mitre_summary,
                'ai_analysis': ai_analysis,
                'reports': reports,
            }
            
            self._display_summary()
            
            return self.results
        
        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            raise
    
    def _parse_logs(self) -> dict:
        """Parse network logs"""
        try:
            parser = LogParser(self.csv_path)
            df = parser.parse()
            logger.info(f"[+] Parsed {len(df)} log records")
            logger.info(f"[+] Extracted {df['Destination IP'].nunique()} unique destination IPs")
            return {'dataframe': df}
        except Exception as e:
            logger.error(f"Error parsing logs: {e}")
            raise
    
    def _enrich_ips(self, parsed_data: dict) -> list:
        """Enrich IPs with threat intelligence"""
        try:
            df = parsed_data['dataframe']
            enricher = IPEnricher()
            
            unique_ips = df['Destination IP'].unique()
            logger.info(f"Enriching {len(unique_ips)} unique IPs...")
            
            enriched_results = []
            for ip in unique_ips:
                try:
                    enriched = enricher.enrich_ip(ip)
                    enriched_results.append(enriched)
                except Exception as e:
                    logger.debug(f"Error enriching {ip}: {e}")
            
            logger.info(f"[+] Enriched {len(enriched_results)} IPs")
            
            # Display classification summary
            classifications = {}
            for result in enriched_results:
                classification = result.get('classification', 'UNKNOWN')
                classifications[classification] = classifications.get(classification, 0) + 1
            
            for classification, count in classifications.items():
                logger.info(f"  {classification}: {count} IPs")
            
            return enriched_results
        
        except Exception as e:
            logger.error(f"Error enriching IPs: {e}")
            raise
    
    def _run_advanced_analysis(self, parsed_data: dict, enriched_results: list) -> dict:
        """Run advanced threat hunting analysis"""
        try:
            df = parsed_data['dataframe']
            analyzer = AdvancedAnalyzer(df, enriched_results)
            analysis = analyzer.run_all_analysis()
            
            logger.info("[+] Advanced analysis complete")
            logger.info(f"  - Destinations analyzed: {analysis.get('destination_analysis', {}).get('total_destinations', 0)}")
            logger.info(f"  - Possible beacons detected: {len(analysis.get('beaconing_analysis', {}).get('possible_beacons', {}))}")
            logger.info(f"  - C2 contacts found: {len(analysis.get('c2_indicators', {}).get('known_c2_contacts', {}))}")
            
            return analysis
        
        except Exception as e:
            logger.error(f"Error in advanced analysis: {e}")
            raise
    
    def _run_temporal_analysis(self, parsed_data: dict) -> dict:
        """Run temporal analysis"""
        try:
            df = parsed_data['dataframe']
            analyzer = TimeBasedAnalyzer(df)
            analysis = analyzer.analyze_temporal_patterns()
            
            logger.info("[+] Temporal analysis complete")
            
            return analysis
        
        except Exception as e:
            logger.error(f"Error in temporal analysis: {e}")
            return {}
    
    def _calculate_risk_scores(self, enriched_results: list, advanced_analysis: dict) -> dict:
        """Calculate risk scores"""
        try:
            engine = RiskScoringEngine(enriched_results, advanced_analysis)
            overall_score, severity = engine.calculate_overall_risk()
            host_scores = engine.calculate_host_risk_scores()
            risk_summary = engine.get_risk_summary()
            
            logger.info("[+] Risk scoring complete")
            logger.info(f"  - Overall Risk Score: {overall_score} ({severity})")
            logger.info(f"  - Critical hosts: {risk_summary.get('critical_host_count', 0)}")
            logger.info(f"  - High-risk hosts: {risk_summary.get('high_risk_host_count', 0)}")
            
            return risk_summary
        
        except Exception as e:
            logger.error(f"Error calculating risk scores: {e}")
            raise
    
    def _map_mitre(self, advanced_analysis: dict, enriched_results: list) -> dict:
        """Map to MITRE ATT&CK framework"""
        try:
            mapper = MITREMapper(advanced_analysis, enriched_results)
            summary = mapper.get_mitre_summary()
            
            logger.info("[+] MITRE ATT&CK mapping complete")
            logger.info(f"  - Total techniques mapped: {summary.get('total_techniques', 0)}")
            
            for tactic, techniques in summary.get('by_tactic', {}).items():
                logger.info(f"  - {tactic}: {len(techniques)} techniques")
            
            return summary
        
        except Exception as e:
            logger.error(f"Error mapping MITRE: {e}")
            raise
    
    def _generate_reports(self, enriched_results: list, advanced_analysis: dict, risk_summary: dict, mitre_summary: dict, 
                          ai_analysis: dict = None) -> dict:
        """Generate professional reports"""
        try:
            generator = AdvancedReportGenerator()
            
            reports = {
                'executive_report': generator.generate_executive_report(risk_summary, mitre_summary, enriched_results),
                'technical_report': generator.generate_technical_report(advanced_analysis, enriched_results, mitre_summary),
                'threat_hunting_report': generator.generate_threat_hunting_report(advanced_analysis),
                'comprehensive_findings': generator.generate_comprehensive_findings_report(enriched_results, advanced_analysis, risk_summary, ai_analysis),
            }
            
            # Save reports
            for report_type, content in reports.items():
                filepath = generator.save_report(report_type, content)
                logger.info(f"[+] {report_type} saved to {filepath}")
            
            return reports
        
        except Exception as e:
            logger.error(f"Error generating reports: {e}")
            raise
    
    def _run_ai_analysis(self, enriched_results: list, advanced_analysis: dict, risk_summary: dict, 
                          parsed_data: dict = None) -> dict:
        """Run AI threat analysis with raw logs"""
        try:
            ai_analyzer = AIThreatAnalyzer(provider=self.ai_provider, api_key=self.ai_key)
            
            # Pass raw dataframe to AI for detailed analysis
            df = parsed_data.get('dataframe') if parsed_data else None
            analysis = ai_analyzer.analyze_threat_report(enriched_results, advanced_analysis, risk_summary, df)
            
            if analysis.get('status') == 'success':
                logger.info("[+] AI threat analysis complete")
                return analysis
            else:
                logger.warning(f"AI analysis failed: {analysis.get('error')}")
                return analysis
        
        except Exception as e:
            logger.error(f"Error in AI analysis: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _display_summary(self):
        """Display analysis summary"""
        logger.info("\n" + "="*80)
        logger.info("THREAT HUNTING ANALYSIS COMPLETE")
        logger.info("="*80)
        
        risk_summary = self.results.get('risk_summary', {})
        logger.info(f"\nOverall Risk Score: {risk_summary.get('overall_risk_score', 0)}/100 ({risk_summary.get('overall_severity', 'UNKNOWN')})")
        
        mitre_summary = self.results.get('mitre_summary', {})
        logger.info(f"MITRE ATT&CK Techniques Mapped: {mitre_summary.get('total_techniques', 0)}")
        
        logger.info("\nKey Metrics:")
        logger.info(f"  - Critical hosts: {risk_summary.get('critical_host_count', 0)}")
        logger.info(f"  - High-risk hosts: {risk_summary.get('high_risk_host_count', 0)}")
        
        logger.info("\n" + "="*80)
    
    def print_executive_summary(self):
        """Print executive summary to console"""
        if 'reports' not in self.results:
            logger.warning("No reports generated yet. Run complete_analysis() first.")
            return
        
        print("\n" + "="*80)
        print(self.results['reports'].get('executive_report', 'No report available'))
        print("="*80)
    
    def print_technical_summary(self):
        """Print technical summary to console"""
        if 'reports' not in self.results:
            logger.warning("No reports generated yet. Run complete_analysis() first.")
            return
        
        print("\n" + "="*80)
        print(self.results['reports'].get('technical_report', 'No report available'))
        print("="*80)
    
    def print_comprehensive_findings(self):
        """Print comprehensive findings report to console"""
        if 'reports' not in self.results:
            logger.warning("No reports generated yet. Run complete_analysis() first.")
            return
        
        print("\n" + "="*80)
        print(self.results['reports'].get('comprehensive_findings', 'No findings report available'))
        print("="*80)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Local Threat Hunting with Ollama')
    parser.add_argument('--csv', default='data/logs.csv', help='Path to CSV log file')
    parser.add_argument('--ai-provider', default='ollama', choices=['ollama', 'none'], 
                       help='AI provider (ollama=local, none=skip AI)')
    args = parser.parse_args()
    
    csv_path = args.csv
    
    # Initialize threat hunter with local Ollama
    hunter = IntegratedThreatHunter(csv_path, ai_provider=args.ai_provider, ai_key=None)
    
    # Run complete analysis
    results = hunter.run_complete_analysis()
    
    # Display summaries
    hunter.print_executive_summary()
    
    # Display comprehensive findings
    logger.info("\n" + "="*80)
    logger.info("DISPLAYING COMPREHENSIVE FINDINGS REPORT")
    logger.info("="*80)
    hunter.print_comprehensive_findings()
    
    # Display AI analysis if available
    if results.get('ai_analysis', {}).get('status') == 'success':
        logger.info("\n" + "="*80)
        logger.info("AI DEEP ANALYSIS")
        logger.info("="*80)
        print(results['ai_analysis'].get('analysis', 'AI analysis completed'))
        print("="*80)
    
    logger.info("\nAnalysis complete! Check the 'reports/' directory for detailed reports.")


if __name__ == '__main__':
    main()
