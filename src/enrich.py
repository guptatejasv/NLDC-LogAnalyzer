"""
IP Enrichment Module
Enriches IP addresses with threat intelligence data from VirusTotal and AbuseIPDB APIs
"""

import requests
import json
import time
import logging
from typing import Dict, Optional
from pathlib import Path
from datetime import datetime, timedelta
from config.config import Config

logger = logging.getLogger(__name__)


class CacheManager:
    """Manages caching of API responses to avoid repeated API calls"""
    
    def __init__(self, cache_file: str = None):
        """
        Initialize cache manager
        
        Args:
            cache_file: Path to cache file (default from config)
        """
        self.cache_file = Path(cache_file or Config.CACHE_FILE)
        self.cache_file.parent.mkdir(exist_ok=True)
        self.cache = self._load_cache()
    
    def _load_cache(self) -> Dict:
        """Load cache from file"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Could not load cache: {e}")
                return {}
        return {}
    
    def _save_cache(self):
        """Save cache to file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except IOError as e:
            logger.warning(f"Could not save cache: {e}")
    
    def get(self, ip: str, api_type: str) -> Optional[Dict]:
        """
        Get cached data for an IP
        
        Args:
            ip: IP address
            api_type: Type of API ('vt' or 'abuseipdb')
            
        Returns:
            Cached data if exists and not expired, None otherwise
        """
        if not Config.ENABLE_CACHING:
            return None
        
        key = f"{ip}_{api_type}"
        if key in self.cache:
            cached_item = self.cache[key]
            expiry_time = datetime.fromisoformat(cached_item.get('expiry', ''))
            
            if datetime.now() < expiry_time:
                logger.debug(f"Cache hit for {key}")
                return cached_item.get('data')
            else:
                logger.debug(f"Cache expired for {key}")
                del self.cache[key]
        
        return None
    
    def set(self, ip: str, api_type: str, data: Dict):
        """
        Cache data for an IP
        
        Args:
            ip: IP address
            api_type: Type of API
            data: Data to cache
        """
        if not Config.ENABLE_CACHING:
            return
        
        key = f"{ip}_{api_type}"
        expiry = datetime.now() + timedelta(hours=Config.CACHE_EXPIRY_HOURS)
        
        self.cache[key] = {
            'data': data,
            'expiry': expiry.isoformat(),
            'timestamp': datetime.now().isoformat()
        }
        self._save_cache()
        logger.debug(f"Cached data for {key}")


class IPEnricher:
    """Enriches IP addresses with threat intelligence data"""
    
    def __init__(self):
        """Initialize IP enricher with API credentials"""
        self.vt_api_key = Config.VT_API_KEY
        self.abuse_api_key = Config.ABUSE_API_KEY
        self.cache = CacheManager()
        
        if not self.vt_api_key or not self.abuse_api_key:
            logger.warning("API keys not configured. Some enrichment features may not work.")
    
    def _make_request(self, url: str, headers: Dict, params: Dict = None, 
                     max_retries: int = None) -> Optional[Dict]:
        """
        Make HTTP request with retry logic
        
        Args:
            url: Request URL
            headers: Request headers
            params: Request parameters
            max_retries: Maximum number of retries
            
        Returns:
            Response JSON or None if failed
        """
        max_retries = max_retries or Config.MAX_RETRIES
        
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=Config.REQUEST_TIMEOUT
                )
                
                if response.status_code == 200:
                    logger.debug(f"Successful request to {url}")
                    return response.json()
                elif response.status_code == 429:  # Rate limited
                    wait_time = (attempt + 1) * Config.RETRY_DELAY
                    logger.warning(f"Rate limited. Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                else:
                    logger.warning(f"API returned status {response.status_code}")
                    return None
                    
            except requests.exceptions.Timeout:
                logger.warning(f"Request timeout on attempt {attempt + 1}/{max_retries}")
            except requests.exceptions.RequestException as e:
                logger.warning(f"Request error on attempt {attempt + 1}/{max_retries}: {e}")
        
        logger.error(f"Failed to get response from {url} after {max_retries} attempts")
        return None
    
    def enrich_virustotal(self, ip: str) -> Dict:
        """
        Enrich IP with VirusTotal data
        
        Args:
            ip: IP address to enrich
            
        Returns:
            Dictionary with VirusTotal data
        """
        if not self.vt_api_key:
            logger.warning(f"VirusTotal API key not configured")
            return {
                'status': 'error',
                'message': 'API key not configured',
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0
            }
        
        # Check cache first
        cached_data = self.cache.get(ip, 'vt')
        if cached_data:
            return cached_data
        
        url = f"{Config.VT_BASE_URL}/ip_addresses/{ip}"
        headers = {
            'x-apikey': self.vt_api_key,
            'User-Agent': 'Log-Analyzer-AI/1.0'
        }
        
        try:
            response = self._make_request(url, headers)
            
            if response and 'data' in response:
                data = response['data']
                attributes = data.get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                
                result = {
                    'status': 'success',
                    'malicious': last_analysis_stats.get('malicious', 0),
                    'suspicious': last_analysis_stats.get('suspicious', 0),
                    'harmless': last_analysis_stats.get('harmless', 0),
                    'undetected': last_analysis_stats.get('undetected', 0),
                    'country': attributes.get('country', 'Unknown'),
                    'asn': attributes.get('asn', 'Unknown')
                }
                
                # Cache the result
                self.cache.set(ip, 'vt', result)
                return result
            else:
                return {
                    'status': 'error',
                    'message': 'No data returned from API',
                    'malicious': 0,
                    'suspicious': 0,
                    'harmless': 0
                }
                
        except Exception as e:
            logger.error(f"Error enriching {ip} with VirusTotal: {e}")
            return {
                'status': 'error',
                'message': str(e),
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0
            }
    
    def enrich_abuseipdb(self, ip: str) -> Dict:
        """
        Enrich IP with AbuseIPDB data
        
        Args:
            ip: IP address to enrich
            
        Returns:
            Dictionary with AbuseIPDB data
        """
        if not self.abuse_api_key:
            logger.warning(f"AbuseIPDB API key not configured")
            return {
                'status': 'error',
                'message': 'API key not configured',
                'abuseConfidenceScore': 0,
                'usageType': 'Unknown',
                'totalReports': 0
            }
        
        # Check cache first
        cached_data = self.cache.get(ip, 'abuseipdb')
        if cached_data:
            return cached_data
        
        url = f"{Config.ABUSE_BASE_URL}/check"
        headers = {
            'Key': self.abuse_api_key,
            'Accept': 'application/json',
            'User-Agent': 'Log-Analyzer-AI/1.0'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': ''
        }
        
        try:
            response = self._make_request(url, headers, params)
            
            if response and 'data' in response:
                data = response['data']
                
                result = {
                    'status': 'success',
                    'abuseConfidenceScore': data.get('abuseConfidenceScore', 0),
                    'usageType': data.get('usageType', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'domain': data.get('domain', 'Unknown'),
                    'totalReports': data.get('totalReports', 0),
                    'lastReportedAt': data.get('lastReportedAt', 'Never')
                }
                
                # Cache the result
                self.cache.set(ip, 'abuseipdb', result)
                return result
            else:
                return {
                    'status': 'error',
                    'message': 'No data returned from API',
                    'abuseConfidenceScore': 0,
                    'usageType': 'Unknown',
                    'totalReports': 0
                }
                
        except Exception as e:
            logger.error(f"Error enriching {ip} with AbuseIPDB: {e}")
            return {
                'status': 'error',
                'message': str(e),
                'abuseConfidenceScore': 0,
                'usageType': 'Unknown',
                'totalReports': 0
            }
    
    def enrich_ip(self, ip: str) -> Dict:
        """
        Enrich IP address with all available threat intelligence
        
        Args:
            ip: IP address to enrich
            
        Returns:
            Dictionary containing enriched data from all sources
        """
        logger.info(f"Enriching IP: {ip}")
        
        enriched_data = {
            'ip': ip,
            'virustotal': self.enrich_virustotal(ip),
            'abuseipdb': self.enrich_abuseipdb(ip),
            'enrichment_timestamp': datetime.now().isoformat()
        }
        
        return enriched_data
