"""
Configuration management for Log Analyzer AI
Loads settings from environment variables and provides centralized configuration
"""

import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from .env file
load_dotenv()


class Config:
    """Application configuration class"""
    
    # API Keys
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    ABUSE_API_KEY = os.getenv("ABUSE_API_KEY", "")
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
    
    # API Endpoints
    VT_BASE_URL = "https://www.virustotal.com/api/v3"
    ABUSE_BASE_URL = "https://api.abuseipdb.com/api/v2"
    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
    
    # AI Model Configuration
    AI_MODEL = os.getenv("AI_MODEL", "mistralai/mistral-7b-instruct:free")
    USE_OPENROUTER = os.getenv("USE_OPENROUTER", "True").lower() == "true"
    
    # Request Settings
    REQUEST_TIMEOUT = 10
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds
    
    # Caching
    ENABLE_CACHING = os.getenv("ENABLE_CACHING", "True").lower() == "true"
    CACHE_EXPIRY_HOURS = int(os.getenv("CACHE_EXPIRY_HOURS", "24"))
    CACHE_FILE = "cache/ip_cache.json"
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = "logs/analyzer.log"
    
    # Data paths
    DATA_DIR = Path(__file__).parent.parent / "data"
    LOGS_DIR = Path(__file__).parent.parent / "logs"
    CACHE_DIR = Path(__file__).parent.parent / "cache"
    
    # Create necessary directories
    @staticmethod
    def create_directories():
        """Create necessary directories if they don't exist"""
        Config.LOGS_DIR.mkdir(exist_ok=True)
        Config.CACHE_DIR.mkdir(exist_ok=True)


# Initialize directories
Config.create_directories()
