"""
AI Threat Analysis Module
Integrates with LLM (Ollama/OpenRouter) for advanced threat analysis
"""

import logging
import json
from typing import Dict, List, Any, Optional
import requests
import pandas as pd

logger = logging.getLogger(__name__)


class AIThreatAnalyzer:
    """Integrates LLM models for advanced threat analysis"""
    
    def __init__(self, provider: str = 'openrouter', api_key: Optional[str] = None):
        """
        Initialize AI analyzer
        
        Args:
            provider: 'ollama' or 'openrouter'
            api_key: API key for OpenRouter
        """
        self.provider = provider
        self.api_key = api_key
        self.model = 'deepseek-r1:8b' if provider == 'ollama' else 'deepseek/deepseek-r1'
        self.ollama_base = 'http://localhost:11434'
        self.openrouter_base = 'https://openrouter.ai/api/v1'
    
    def _compress_prompt(self, prompt: str) -> str:
        """Compress prompt by removing verbose sections and redundant data"""
        lines = prompt.split('\n')
        compressed = []
        
        for line in lines:
            # Skip very verbose sections
            if any(skip in line for skip in [
                'OPTIONAL:',
                'For detailed analysis',
                'DELIVERABLES:',
                'CRITICAL ANALYSIS REQUIREMENTS:',
            ]):
                continue
            
            # Remove redundant whitespace
            line = line.strip()
            if line and len(compressed) < len(lines) * 0.7:  # Keep 70% of lines
                compressed.append(line)
        
        return '\n'.join(compressed)
    
    def analyze_threat_report(self, enriched_results: List[Dict], advanced_analysis: Dict, risk_summary: Dict, 
                               df: pd.DataFrame = None) -> Dict[str, Any]:
        """
        Analyze threat report using LLM with raw logs
        
        Args:
            enriched_results: List of enriched IP data
            advanced_analysis: Advanced analysis results
            risk_summary: Risk scoring summary
            df: Raw logs dataframe for detailed analysis
            
        Returns:
            LLM analysis results
        """
        # Skip AI analysis if provider is 'none'
        if self.provider == 'none':
            logger.info("AI analysis skipped (provider=none)")
            return {'status': 'skipped', 'message': 'AI analysis disabled'}
        
        logger.info(f"Requesting AI analysis via {self.provider}")
        
        # Build analysis prompt with raw logs
        prompt = self._build_analysis_prompt(enriched_results, advanced_analysis, risk_summary, df)
        
        if self.provider == 'ollama':
            return self._analyze_with_ollama(prompt)
        elif self.provider == 'openrouter':
            return self._analyze_with_openrouter(prompt)
        else:
            logger.error(f"Unknown provider: {self.provider}")
            return {'error': f'Unknown provider: {self.provider}'}
    
    def _extract_suspicious_clean_ips(self, df: pd.DataFrame, enriched_results: List[Dict]) -> Dict[str, Any]:
        """Extract suspicious patterns from clean IPs"""
        clean_ips = [r.get('ip') for r in enriched_results if r.get('classification') in ['CLEAN', 'UNKNOWN']]
        
        suspicious_patterns = {}
        
        if not clean_ips or df is None:
            return suspicious_patterns
        
        try:
            # Check for high frequency communications to clean IPs
            df_copy = df.copy()
            if 'Destination IP' in df_copy.columns:
                for clean_ip in clean_ips[:10]:  # Check top 10 clean IPs
                    ip_traffic = df_copy[df_copy['Destination IP'] == clean_ip]
                    
                    if len(ip_traffic) > 10:  # High frequency
                        ports = ip_traffic.get('Destination Port', pd.Series([])).unique() if 'Destination Port' in ip_traffic.columns else []
                        suspicious_patterns[clean_ip] = {
                            'traffic_count': len(ip_traffic),
                            'unique_ports': len(ports),
                            'ports': ports.tolist() if hasattr(ports, 'tolist') else list(ports),
                            'pattern': 'High frequency communication',
                        }
        except Exception as e:
            logger.debug(f"Error extracting suspicious clean IPs: {e}")
        
        return suspicious_patterns
    
    def _build_analysis_prompt(self, enriched_results: List[Dict], advanced_analysis: Dict, risk_summary: Dict,
                               df: pd.DataFrame = None) -> str:
        """Build comprehensive analysis prompt with raw logs"""
        
        # Extract key data
        critical_hosts = risk_summary.get('critical_hosts', [])
        high_risk_hosts = risk_summary.get('high_risk_hosts', [])
        overall_score = risk_summary.get('overall_risk_score', 0)
        overall_severity = risk_summary.get('overall_severity', 'UNKNOWN')
        
        # Extract findings
        beacons = advanced_analysis.get('beaconing_analysis', {}).get('possible_beacons', {})
        c2_indicators = advanced_analysis.get('c2_indicators', {})
        lateral_movement = advanced_analysis.get('lateral_movement', {})
        attack_patterns = advanced_analysis.get('attack_patterns', {})
        
        # Extract suspicious clean IPs
        suspicious_clean = self._extract_suspicious_clean_ips(df, enriched_results)
        
        # Prepare raw log samples
        raw_log_samples = self._prepare_raw_log_samples(df, enriched_results) if df is not None else {}
        
        # IP Classification summary
        malicious_ips = [r.get('ip') for r in enriched_results if r.get('classification') == 'MALICIOUS']
        suspicious_ips = [r.get('ip') for r in enriched_results if r.get('classification') == 'SUSPICIOUS']
        clean_ips = [r.get('ip') for r in enriched_results if r.get('classification') in ['CLEAN', 'UNKNOWN']]
        
        prompt = f"""
You are a Senior SOC Analyst, Threat Hunter, and Incident Responder with 15+ years of experience.

ANALYSIS DIRECTIVE:
Analyze the network security investigation results provided below. DO NOT simply repeat findings.
Provide EXPERT-LEVEL analysis that a CISO or Security Architect would find valuable.
Focus on hidden patterns, attack indicators, and ALSO suspicious behavior in supposedly "clean" IPs.
IMPORTANT: Verify if clean IPs are actually clean or if they exhibit suspicious patterns.

SECURITY INVESTIGATION RESULTS:
{"="*80}

OVERALL THREAT ASSESSMENT:
- Risk Score: {overall_score}/100 ({overall_severity})
- Critical Hosts: {len(critical_hosts)}
- High-Risk Hosts: {len(high_risk_hosts)}

IP CLASSIFICATION SUMMARY:
- Malicious IPs: {len(malicious_ips)} → {malicious_ips}
- Suspicious IPs: {len(suspicious_ips)} → {suspicious_ips}
- Clean/Unknown IPs: {len(clean_ips)} → {clean_ips[:10]}

THREAT INDICATORS:

1. COMMAND & CONTROL INDICATORS:
   - Possible Beacons: {len(beacons)}
   - Known C2 Contacts: {len(c2_indicators.get('known_c2_contacts', {}))}
   - Malicious Infrastructure: {len(c2_indicators.get('malicious_infrastructure', {}))}

2. ATTACK PATTERNS DETECTED:
   - Malware Patterns: {len(attack_patterns.get('malware_indicators', {}))}
   - Reconnaissance Patterns: {len(attack_patterns.get('reconnaissance_patterns', {}))}
   - Lateral Movement Patterns: {len(attack_patterns.get('lateral_movement_indicators', {}))}

3. LATERAL MOVEMENT:
   - Internal Communications: {lateral_movement.get('internal_communications', {}).get('count', 0)}
   - Suspicious Internal Ports: {len(lateral_movement.get('suspicious_port_usage', {}))}

4. SUSPICIOUS PATTERNS IN CLEAN IPs:
   - Clean IPs with suspicious behavior: {len(suspicious_clean)}
   - Details: {json.dumps(suspicious_clean, indent=2, default=str) if suspicious_clean else 'None detected'}

RAW LOG SAMPLES (For context):
{json.dumps(raw_log_samples, indent=2, default=str)}

DETAILED DATA:
{json.dumps({
    'critical_hosts': critical_hosts[:5],
    'beacons': list(beacons.items())[:3],
    'c2_data': c2_indicators,
    'malicious_ips_summary': {ip: [r for r in enriched_results if r.get('ip') == ip][0] if [r for r in enriched_results if r.get('ip') == ip] else {} for ip in malicious_ips[:5]},
}, indent=2, default=str)}

{"="*80}

CRITICAL ANALYSIS REQUIREMENTS:

1. IP CLASSIFICATION VERIFICATION
   - Verify if "Clean" IPs are actually clean
   - Identify clean IPs that show suspicious communication patterns
   - Flag any IPs that may be compromised internal systems

2. THREAT HUNTING INSIGHTS
   - Identify hidden attack indicators (especially in clean IPs)
   - Discover unusual patterns a human analyst might miss
   - Assess attack progression and sophistication level
   - Find IPs that might be proxies or redirects

3. BEHAVIORAL ANALYSIS
   - Characterize the attacker's behavior
   - Identify malware families or attack frameworks (if possible)
   - Assess attacker maturity level (script kiddie to nation-state)
   - Analyze if clean IPs are compromised systems participating in attack

4. ATTACK KILL CHAIN
   - Map the attack progression
   - Identify initial compromise indicators
   - Trace lateral movement and objective phases
   - Estimate attack timeline

5. IP-LEVEL FINDINGS
   - For EACH IP: Is it truly malicious/suspicious/clean?
   - Why is it classified that way?
   - What evidence supports this classification?
   - Any contradictions between external classification and traffic patterns?

6. BUSINESS IMPACT ASSESSMENT
   - Potential data at risk
   - System criticality that may be compromised
   - Probable attack objectives

7. IMMEDIATE RISKS
   - Current active threats
   - Ongoing data exfiltration indicators
   - Active C2 communication
   - Compromised clean IPs (internal systems)

8. CONFIDENCE LEVELS & ASSUMPTIONS
   - State confidence in each finding (HIGH/MEDIUM/LOW)
   - List any assumptions made
   - Identify data gaps

DELIVERABLES:
- Executive summary (3-4 sentences)
- Detailed IP classification findings
- Hidden patterns discovered
- Behavioral assessment
- Risk prioritization (What to block/monitor first?)
- Recommended immediate actions
- Each finding should include confidence level
"""
        
        return prompt
    
    def _prepare_raw_log_samples(self, df: pd.DataFrame, enriched_results: List[Dict]) -> Dict[str, Any]:
        """Prepare raw log samples for AI analysis"""
        try:
            samples = {}
            
            # Get malicious IPs
            malicious_ips = [r.get('ip') for r in enriched_results if r.get('classification') == 'MALICIOUS']
            
            # Sample logs for top malicious IPs
            for ip in malicious_ips[:3]:
                if 'Destination IP' in df.columns:
                    ip_logs = df[df['Destination IP'] == ip].head(5)
                    if len(ip_logs) > 0:
                        samples[f'Malicious_IP_{ip}'] = ip_logs[[col for col in ['Date', 'Source IP', 'Destination IP', 'Destination Port', 'Action'] if col in df.columns]].to_dict('records')
            
            # Get suspicious IPs
            suspicious_ips = [r.get('ip') for r in enriched_results if r.get('classification') == 'SUSPICIOUS']
            for ip in suspicious_ips[:2]:
                if 'Destination IP' in df.columns:
                    ip_logs = df[df['Destination IP'] == ip].head(5)
                    if len(ip_logs) > 0:
                        samples[f'Suspicious_IP_{ip}'] = ip_logs[[col for col in ['Date', 'Source IP', 'Destination IP', 'Destination Port', 'Action'] if col in df.columns]].to_dict('records')
            
            # Get samples of clean IP logs
            clean_ips = [r.get('ip') for r in enriched_results if r.get('classification') in ['CLEAN', 'UNKNOWN']]
            for ip in clean_ips[:2]:
                if 'Destination IP' in df.columns:
                    ip_logs = df[df['Destination IP'] == ip].head(5)
                    if len(ip_logs) > 0:
                        samples[f'Clean_IP_{ip}'] = ip_logs[[col for col in ['Date', 'Source IP', 'Destination IP', 'Destination Port', 'Action'] if col in df.columns]].to_dict('records')
            
            return {'raw_log_samples': samples, 'total_logs': len(df)}
        except Exception as e:
            logger.debug(f"Error preparing raw log samples: {e}")
            return {'error': str(e)}
    
    def _analyze_with_ollama(self, prompt: str) -> Dict[str, Any]:
        """Analyze using local Ollama with retry logic and timeout handling"""
        max_retries = 2
        timeout_seconds = 120  # 2 minutes instead of 5
        retry_delay = 5  # seconds
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Connecting to Ollama at {self.ollama_base} (attempt {attempt + 1}/{max_retries})")
                
                # Compress prompt if too large
                if len(prompt) > 6000:
                    logger.warning(f"Prompt is large ({len(prompt)} chars), compressing...")
                    prompt = self._compress_prompt(prompt)
                    logger.info(f"Compressed prompt to {len(prompt)} chars")
                
                response = requests.post(
                    f'{self.ollama_base}/api/generate',
                    json={
                        'model': self.model,
                        'prompt': prompt,
                        'stream': False,
                        'temperature': 0.7,
                    },
                    timeout=timeout_seconds,
                )
                
                if response.status_code == 200:
                    result = response.json()
                    return {
                        'status': 'success',
                        'provider': 'ollama',
                        'model': self.model,
                        'analysis': result.get('response', ''),
                    }
                else:
                    logger.error(f"Ollama returned status {response.status_code}")
                    if attempt < max_retries - 1:
                        logger.info(f"Retrying in {retry_delay} seconds...")
                        import time
                        time.sleep(retry_delay)
                        continue
                    return {'status': 'error', 'error': f'Ollama returned {response.status_code}'}
            
            except requests.exceptions.Timeout:
                logger.error(f"Ollama request timed out after {timeout_seconds}s (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    logger.info(f"Retrying with longer timeout...")
                    timeout_seconds += 60  # Increase timeout for next attempt
                    import time
                    time.sleep(retry_delay)
                    continue
                return {
                    'status': 'error',
                    'error': f'Ollama request timed out after {timeout_seconds}s. Model may be too slow or system is overloaded.',
                    'suggestion': 'Try a smaller model: ollama pull mistral:7b'
                }
            
            except requests.exceptions.ConnectionError:
                logger.error("Cannot connect to Ollama. Is it running?")
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    import time
                    time.sleep(retry_delay)
                    continue
                return {
                    'status': 'error',
                    'error': 'Ollama not available. Start with: ollama serve',
                    'fallback': 'Using rule-based analysis only'
                }
            
            except Exception as e:
                logger.error(f"Ollama analysis error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    import time
                    time.sleep(retry_delay)
                    continue
                return {'status': 'error', 'error': str(e)}
        
        return {'status': 'error', 'error': 'All retry attempts failed'}
    
    def _analyze_with_openrouter(self, prompt: str) -> Dict[str, Any]:
        """Analyze using OpenRouter with better error handling"""
        if not self.api_key:
            logger.error("OpenRouter API key not provided")
            return {'status': 'error', 'error': 'OpenRouter API key required'}
        
        timeout_seconds = 60  # Reduced from 120
        
        try:
            logger.info("Connecting to OpenRouter")
            
            response = requests.post(
                f'{self.openrouter_base}/chat/completions',
                headers={
                    'Authorization': f'Bearer {self.api_key}',
                    'Content-Type': 'application/json',
                },
                json={
                    'model': self.model,
                    'messages': [
                        {
                            'role': 'system',
                            'content': 'You are a Senior SOC Analyst and Threat Hunter with 15+ years of experience.'
                        },
                        {
                            'role': 'user',
                            'content': prompt
                        }
                    ],
                    'temperature': 0.7,
                    'max_tokens': 4000,
                },
                timeout=timeout_seconds,
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'status': 'success',
                    'provider': 'openrouter',
                    'model': self.model,
                    'analysis': result.get('choices', [{}])[0].get('message', {}).get('content', ''),
                }
            else:
                logger.error(f"OpenRouter error: {response.status_code}")
                error_detail = response.text if response.text else str(response.status_code)
                return {'status': 'error', 'error': f'OpenRouter error: {error_detail}'}
        
        except requests.exceptions.Timeout:
            logger.error(f"OpenRouter request timed out after {timeout_seconds}s")
            return {
                'status': 'error',
                'error': f'OpenRouter request timed out after {timeout_seconds}s'
            }
        
        except Exception as e:
            logger.error(f"OpenRouter analysis error: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def generate_incident_report(self, analysis: Dict) -> Dict[str, Any]:
        """Generate formatted incident report from AI analysis"""
        if analysis.get('status') != 'success':
            return {
                'status': 'error',
                'report': f"AI analysis failed: {analysis.get('error', 'Unknown error')}",
            }
        
        raw_analysis = analysis.get('analysis', '')
        
        return {
            'status': 'success',
            'ai_model': analysis.get('model'),
            'provider': analysis.get('provider'),
            'report': raw_analysis,
            'sections': self._parse_analysis_sections(raw_analysis),
        }
    
    def _parse_analysis_sections(self, analysis_text: str) -> Dict[str, str]:
        """Parse analysis into sections"""
        sections = {
            'executive_summary': '',
            'threat_assessment': '',
            'kill_chain': '',
            'business_impact': '',
            'immediate_risks': '',
            'recommendations': '',
        }
        
        current_section = None
        
        for line in analysis_text.split('\n'):
            line_lower = line.lower()
            
            if 'executive' in line_lower and 'summary' in line_lower:
                current_section = 'executive_summary'
            elif 'threat' in line_lower or 'assessment' in line_lower:
                current_section = 'threat_assessment'
            elif 'kill chain' in line_lower:
                current_section = 'kill_chain'
            elif 'business' in line_lower and 'impact' in line_lower:
                current_section = 'business_impact'
            elif 'immediate' in line_lower and 'risk' in line_lower:
                current_section = 'immediate_risks'
            elif 'recommendation' in line_lower:
                current_section = 'recommendations'
            
            if current_section and line.strip():
                sections[current_section] += line + '\n'
        
        return {k: v.strip() for k, v in sections.items() if v.strip()}
