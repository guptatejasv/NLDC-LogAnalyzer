"""
CSV Log Parser Module
Handles reading and parsing network security logs from CSV files
"""

import pandas as pd
from pathlib import Path
from typing import List, Set
import logging

logger = logging.getLogger(__name__)


class LogParser:
    """Parse network security logs from CSV files"""
    
    def __init__(self, csv_path: str):
        """
        Initialize the log parser
        
        Args:
            csv_path: Path to the CSV file
            
        Raises:
            FileNotFoundError: If CSV file doesn't exist
        """
        self.csv_path = Path(csv_path)
        
        if not self.csv_path.exists():
            raise FileNotFoundError(f"CSV file not found: {csv_path}")
        
        logger.info(f"Initializing LogParser with file: {csv_path}")
        self.df = None
        self.destination_ips = set()
    
    def parse(self) -> pd.DataFrame:
        """
        Parse CSV or Excel file.
        """

        try:
            extension = self.csv_path.suffix.lower()

            # ---------- CSV ----------
            if extension == ".csv":

                encodings = ["utf-8", "utf-8-sig", "cp1252", "latin1"]

                for enc in encodings:
                    try:
                        self.df = pd.read_csv(self.csv_path, encoding=enc)
                        logger.info(f"CSV loaded using encoding: {enc}")
                        break
                    except UnicodeDecodeError:
                        continue

                if self.df is None:
                    raise ValueError("Unable to read CSV. Unsupported encoding.")

            # ---------- Excel ----------
            elif extension in [".xlsx", ".xls"]:

                self.df = pd.read_excel(self.csv_path)
                logger.info("Excel file loaded successfully.")

            else:
                raise ValueError(
                    "Unsupported file type. Please upload CSV or Excel."
                )

            logger.info(f"Successfully loaded {len(self.df)} records")

            # -----------------------------
            # Validate Columns
            # -----------------------------

            required_columns = [
                "Source IP",
                "Destination IP"
            ]

            port_columns = [
                "Port",
                "Destination Port"
            ]

            missing_columns = [
                col for col in required_columns
                if col not in self.df.columns
            ]

            has_port = any(
                col in self.df.columns
                for col in port_columns
            )

            if missing_columns or not has_port:
                raise ValueError(
                    f"Missing required columns. Required: {required_columns} and one of {port_columns}"
                )

            if "Destination Port" in self.df.columns and "Port" not in self.df.columns:
                self.df["Port"] = self.df["Destination Port"]

            return self.df

        except Exception as e:
            logger.error(e)
            raise
    
    def extract_destination_ips(self) -> Set[str]:
        """
        Extract unique destination IPs from the logs
        
        Returns:
            Set of unique destination IP addresses
            
        Raises:
            RuntimeError: If parse() hasn't been called first
        """
        if self.df is None:
            raise RuntimeError("Must call parse() before extracting IPs")
        
        try:
            # Get unique destination IPs and filter out invalid ones
            self.destination_ips = set(
                self.df['Destination IP'].unique()
            )
            
            # Filter out empty or null values
            self.destination_ips = {
                ip for ip in self.destination_ips 
                if ip and isinstance(ip, str) and ip.strip()
            }
            
            logger.info(f"Extracted {len(self.destination_ips)} unique destination IPs")
            return self.destination_ips
            
        except Exception as e:
            logger.error(f"Error extracting destination IPs: {e}")
            raise
    
    def categorize_communication(self):
        """
        Categorize communication based on destination port and connection type.
        Adds 'Service' and 'Communication Type' columns to the DataFrame.
        """
        if self.df is None:
            raise RuntimeError("Must call parse() before categorizing communication")

        _COMMON_PORTS = {
            20: 'FTP Data',
            21: 'FTP Control',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            67: 'DHCP',
            68: 'DHCP',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            3389: 'RDP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            8080: 'HTTP-Alt',
            27017: 'MongoDB',
        }

        def get_service(port):
            return _COMMON_PORTS.get(port, 'Other')

        self.df['Service'] = self.df['Destination Port'].apply(get_service)
        self.df['Communication Type'] = self.df['Connection Type'] + ' - ' + self.df['Service']
        logger.info("Categorized communication types based on port and connection type.")
    
    def validate_ip(self, ip: str) -> bool:
        """
        Validate if a string is a valid IP address format
        
        Args:
            ip: IP address to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            
            return True
        except (ValueError, AttributeError):
            return False
    
    def get_logs_by_ip(self, ip: str) -> pd.DataFrame:
        """
        Get all logs associated with a specific destination IP
        
        Args:
            ip: Destination IP address
            
        Returns:
            DataFrame containing logs for the given IP
        """
        if self.df is None:
            raise RuntimeError("Must call parse() before querying logs")
        
        return self.df[self.df['Destination IP'] == ip]
