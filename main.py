"""
Log Analyzer AI - Main Entry Point
Advanced network security log analysis with threat intelligence integration
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
from src.output import ReportGenerator
from config.config import Config

# Setup logger
logger = setup_logger(__name__)


class LogAnalyzerAI:
    """Main application class for analyzing security logs"""
    
    def __init__(self, csv_path: str):
        """
        Initialize the Log Analyzer
        
        Args:
            csv_path: Path to the CSV log file
        """
        self.csv_path = csv_path
        self.parser = None
        self.enricher = IPEnricher()
        self.results = []
        
        logger.info("="*80)
        logger.info("Log Analyzer AI - Starting Application")
        logger.info("="*80)
    
    def run(self):
        """Execute the complete analysis pipeline"""
        try:
            # Step 1: Parse logs
            logger.info("\n[STEP 1] Parsing network logs...")
            self._parse_logs()
            
            # Step 2: Extract destination IPs
            logger.info("\n[STEP 2] Extracting destination IPs...")
            destination_ips = self.parser.extract_destination_ips()
            logger.info(f"Found {len(destination_ips)} unique destination IPs")
            
            # Step 3: Validate IPs
            logger.info("\n[STEP 3] Validating IP addresses...")
            valid_ips = [ip for ip in destination_ips if self.parser.validate_ip(ip)]
            invalid_ips = len(destination_ips) - len(valid_ips)
            if invalid_ips > 0:
                logger.warning(f"Found {invalid_ips} invalid IP addresses")
            logger.info(f"Valid IPs: {len(valid_ips)}")
            
            # Step 4: Enrich IPs with threat intelligence
            logger.info("\n[STEP 4] Enriching IPs with threat intelligence...")
            self._enrich_and_classify(valid_ips)
            
            # Step 5: Generate reports
            logger.info("\n[STEP 5] Generating reports...")
            self._generate_reports()
            
            logger.info("\n" + "="*80)
            logger.info("Analysis complete!")
            logger.info("="*80)
            
        except Exception as e:
            logger.error(f"Fatal error during analysis: {e}", exc_info=True)
            print(f"\n{ReportGenerator.RED}ERROR: {e}{ReportGenerator.RESET}")
            sys.exit(1)
    
    def _parse_logs(self):
        """Parse CSV logs and extract data"""
        try:
            self.parser = LogParser(self.csv_path)
            df = self.parser.parse()
            logger.info(f"Successfully parsed CSV with {len(df)} records")
            
        except FileNotFoundError as e:
            logger.error(f"CSV file not found: {e}")
            raise
        except ValueError as e:
            logger.error(f"Invalid CSV format: {e}")
            raise
    
    def _enrich_and_classify(self, ips: list):
        """
        Enrich IPs with threat intelligence and classify them
        
        Args:
            ips: List of IP addresses to analyze
        """
        total_ips = len(ips)
        
        for idx, ip in enumerate(ips, 1):
            try:
                logger.info(f"[{idx}/{total_ips}] Analyzing {ip}...")
                
                # Enrich IP
                enriched_data = self.enricher.enrich_ip(ip)
                
                # Classify
                classification, reasoning = RuleEngine.classify_ip(enriched_data)
                
                # Store result
                result = {
                    'ip': ip,
                    'classification': classification,
                    'reasoning': reasoning,
                    'virustotal': enriched_data.get('virustotal', {}),
                    'abuseipdb': enriched_data.get('abuseipdb', {}),
                    'timestamp': enriched_data.get('enrichment_timestamp')
                }
                
                self.results.append(result)
                
                # Print mini summary
                color = ReportGenerator._get_color_for_classification(classification)
                indicator = ReportGenerator._get_threat_indicator(classification)
                print(f"  {indicator} {color}{classification}{ReportGenerator.RESET} - {reasoning}")
                
            except Exception as e:
                logger.error(f"Error analyzing IP {ip}: {e}")
                # Still add to results with error status
                self.results.append({
                    'ip': ip,
                    'classification': 'ERROR',
                    'reasoning': f'Analysis error: {str(e)}',
                    'virustotal': {'status': 'error'},
                    'abuseipdb': {'status': 'error'}
                })
    
    def _generate_reports(self):
        """Generate and display analysis reports"""
        if not self.results:
            logger.warning("No results to report")
            return
        
        # Executive summary
        ReportGenerator.print_executive_summary(self.results)
        
        # Detailed table view
        ReportGenerator.print_table_view(self.results)
        
        # Detailed individual reports
        ReportGenerator.print_detailed_report(self.results)
        
        # Print detailed analysis for threats
        threats = [r for r in self.results if r['classification'] in ['MALICIOUS', 'SUSPICIOUS', 'POLICY_VIOLATION']]
        if threats:
            logger.info(f"\nDetailed analysis for {len(threats)} threat(s):")
            for result in threats:
                ReportGenerator.print_ip_summary(result)
        
        logger.info(f"\n[SUCCESS] Analysis complete. Processed {len(self.results)} IPs")


def main():
    """Main entry point"""
    
    # Default CSV path
    csv_file = Config.DATA_DIR / "logs.csv"
    
    # Check if custom path provided as argument
    if len(sys.argv) > 1:
        csv_file = Path(sys.argv[1])
    
    # Verify CSV exists
    if not csv_file.exists():
        print(f"{ReportGenerator.RED}Error: CSV file not found: {csv_file}{ReportGenerator.RESET}")
        print(f"\nUsage: python main.py [path_to_csv]")
        print(f"Default path: {csv_file}")
        sys.exit(1)
    
    # Initialize and run analyzer
    analyzer = LogAnalyzerAI(str(csv_file))
    analyzer.run()


if __name__ == "__main__":
    main()
