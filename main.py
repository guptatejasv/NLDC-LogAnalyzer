"""
Log Analyzer AI - Main Entry Point
Advanced network security log analysis with threat intelligence integration
"""

import json
import sys
import logging
from pathlib import Path
from typing import Dict, Generator
import os
from dotenv import load_dotenv
from ollama import Client

# Add project root and src directory to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / 'src'))

from src.logger_setup import setup_logger
from src.parser import LogParser
from src.enrich import IPEnricher
from src.rules import RuleEngine
from src.output import ReportGenerator
from src.communication_analyzer import CommunicationAnalyzer
from config.config import Config

logger = setup_logger(__name__)

client = Client(
    host="https://ollama.com",
    headers={
        "Authorization": f"Bearer {os.getenv('OLLAMA_API_KEY')}"
    }
)


class LogAnalyzerAI:
    """Main application class for analyzing security logs"""

    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        self.parser = None
        self.enricher = IPEnricher()
        self.results = []

        logger.info("=" * 80)
        logger.info("Log Analyzer AI - Starting Application")
        logger.info("=" * 80)

    def run_ip_analysis(self) -> list:
        """
        Executes steps 1-5: parsing, enrichment, classification,
        communication analysis, and report generation.
        Does NOT call the AI executive report (that is streamed separately).
        Returns the list of per-IP results plus the communication_analysis entry.
        """
        try:
            logger.info("\n[STEP 1] Parsing network logs...")
            self._parse_logs()

            logger.info("\n[STEP 2] Extracting destination IPs...")
            destination_ips = self.parser.extract_destination_ips()
            logger.info(f"Found {len(destination_ips)} unique destination IPs")
            logger.info(f"\nDestination IPs: {destination_ips}")

            logger.info("\n[STEP 2.5] Categorizing communication types...")
            self.parser.categorize_communication()

            logger.info("\n[STEP 3] Validating IP addresses...")
            valid_ips = [ip for ip in destination_ips if self.parser.validate_ip(ip)]
            invalid_ips = len(destination_ips) - len(valid_ips)
            if invalid_ips > 0:
                logger.warning(f"Found {invalid_ips} invalid IP addresses")
            logger.info(f"Valid IPs: {len(valid_ips)}")

            logger.info("\n[STEP 4] Enriching IPs with threat intelligence...")
            self._enrich_and_classify(valid_ips)

            logger.info("\n[STEP 4.5] Analyzing communication patterns...")
            communication_analyzer = CommunicationAnalyzer(self.parser.df)
            communication_analysis_results = communication_analyzer.analyze()
            self.results.append({"communication_analysis": communication_analysis_results})
            logger.info(f"Enrichment appended>>>>>>>>>>>>>>>>>>>🪂🪂 {self.results} ")

            logger.info("\n[STEP 5] Generating reports...")
            self._generate_reports()

            logger.info("\n" + "=" * 80)
            logger.info("IP analysis complete!")
            logger.info("=" * 80)

        except Exception as e:
            logger.error(f"Fatal error during analysis: {e}", exc_info=True)
            print(f"\n{ReportGenerator.RED}ERROR: {e}{ReportGenerator.RESET}")
            raise

        return self.results

    def _parse_logs(self):
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

    def _enrich_and_classify(self, ips: list) -> Dict[str, list]:
        total_ips = len(ips)

        for idx, ip in enumerate(ips, 1):
            try:
                logger.info(f"[{idx}/{total_ips}] Analyzing {ip}...")

                enriched_data = self.enricher.enrich_ip(ip)
                logger.info(f"Enriched data for ----------------{ip}: {enriched_data}")

                classification, reasoning = RuleEngine.classify_ip(enriched_data)

                result = {
                    'ip': ip,
                    'classification': classification,
                    'reasoning': reasoning,
                    'virustotal': enriched_data.get('virustotal', {}),
                    'abuseipdb': enriched_data.get('abuseipdb', {}),
                    'timestamp': enriched_data.get('enrichment_timestamp')
                }

                self.results.append(result)

                color = ReportGenerator._get_color_for_classification(classification)
                indicator = ReportGenerator._get_threat_indicator(classification)
                print(f"  {indicator} {color}{classification}{ReportGenerator.RESET} - {reasoning}")

            except Exception as e:
                logger.error(f"Error analyzing IP {ip}: {e}")
                self.results.append({
                    'ip': ip,
                    'classification': 'ERROR',
                    'reasoning': f'Analysis error: {str(e)}',
                    'virustotal': {'status': 'error'},
                    'abuseipdb': {'status': 'error'}
                })
        return self.results

    def _generate_reports(self):
        if not self.results:
            logger.warning("No results to report")
            return

        ReportGenerator.print_executive_summary(self.results)
        ReportGenerator.print_table_view(self.results)
        ReportGenerator.print_detailed_report(self.results)

        comm_results = [r for r in self.results if 'communication_analysis' in r]
        if comm_results and comm_results[0]['communication_analysis']:
            logger.info(f"\n[COMMUNICATION ANALYSIS]")
            ReportGenerator.print_communication_analysis(comm_results[0]['communication_analysis'], self.parser.df)

        threats = [r for r in self.results if r.get('classification') in ['MALICIOUS', 'SUSPICIOUS', 'POLICY_VIOLATION']]
        if threats:
            logger.info(f"\nDetailed analysis for {len(threats)} threat(s):")
            for result in threats:
                ReportGenerator.print_ip_summary(result)

        logger.info(f"\n[SUCCESS] Analysis complete. Processed {len([r for r in self.results if 'ip' in r])} IPs")

    def stream_executive_report(self, analysis_results: list) -> Generator[str, None, None]:
        """
        Streams raw text tokens from the AI model as they arrive.
        Caller is responsible for accumulating/parsing the final JSON if needed.
        """
        logger.info("Generating Executive SOC Report (streaming)...")

        prompt = f"""
                You are a Senior SOC Analyst with 20 years of experience.

                    Your task is to investigate the following firewall/network logs.

                    Threat Intelligence Results:
                    {analysis_results}

                    Perform a complete SOC investigation.
                    and find out the pattern and reasons using that summary and the logs because some finding
                    may be false positive and some may be true positive. So you need to find out the pattern and reason for that also for RAC you'll
                    have to find out why the particular action has been taken on it.

                    Generate ONLY valid JSON.

                    Return the following structure:

                    {{
                        "executive_summary": "...",
                        "risk_level": "Critical | High | Medium | Low",
                        "overall_assessment":"...",

                        "findings":[
                            "...",
                            "...",
                            "..."
                        ],

                        "attack_patterns":[
                            {{
                                "pattern":"...",
                                "description":"..."
                            }}
                        ],

                        "anomalies":[
                            "...",
                            "..."
                        ],

                        "suspicious_behaviors":[
                            "...",
                            "..."
                        ],

                        "possible_attack_types":[
                            "Port Scan",
                            "Brute Force",
                            "Bot Activity",
                            "Malware Communication",
                            "Data Exfiltration",
                            "Beaconing",
                            "C2 Communication"
                        ],

                        "affected_assets":[
                            "...",
                            "..."
                        ],

                        "ioc_summary":{{
                            "malicious_ips":0,
                            "suspicious_ips":0,
                            "clean_ips":0,
                            "unknown_ips":0
                        }},

                        "timeline_analysis":"...",

                        "communication_analysis":"...",

                        "recommended_actions":[
                            "...",
                            "...",
                            "..."
                        ],

                        "mitre_attack":[
                            {{
                                "tactic":"...",
                                "technique":"...",
                                "id":"..."
                            }}
                        ],

                        "priority_actions":[
                            "...",
                            "...",
                            "..."
                        ]
                    }}
                    """

        try:
            stream = client.chat(
                model="gpt-oss:120b",
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.2},
                stream=True
            )

            for chunk in stream:
                if chunk.get("message") and chunk["message"].get("content"):
                    token = chunk["message"]["content"]
                    yield token

            logger.info("Executive SOC Report streaming complete.")

        except Exception as e:
            logger.exception(f"Executive report streaming failed: {e}")
            # Yield an error marker the frontend can detect
            yield json.dumps({"__stream_error__": str(e)})


def main():
    """Main entry point (CLI usage, unchanged)"""
    csv_file = Config.DATA_DIR / "logs.csv"

    if len(sys.argv) > 1:
        csv_file = Path(sys.argv[1])

    if not csv_file.exists():
        print(f"{ReportGenerator.RED}Error: CSV file not found: {csv_file}{ReportGenerator.RESET}")
        print(f"\nUsage: python main.py [path_to_csv]")
        print(f"Default path: {csv_file}")
        sys.exit(1)

    analyzer = LogAnalyzerAI(str(csv_file))
    ip_results = analyzer.run_ip_analysis()

    full_text = ""
    for token in analyzer.stream_executive_report(ip_results):
        print(token, end="", flush=True)
        full_text += token
    print()

    try:
        report = json.loads(full_text)
        print(json.dumps(report, indent=2))
    except json.JSONDecodeError:
        print("Model did not return valid JSON.")


if __name__ == "__main__":
    main()