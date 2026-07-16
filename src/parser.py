"""
CSV/Excel Log Parser Module
Handles reading and parsing network security logs from CSV and Excel files
"""

import pandas as pd
from pathlib import Path
from typing import Set
import logging

logger = logging.getLogger(__name__)


class LogParser:
    """Parse network security logs from CSV/Excel files"""

    def __init__(self, file_path: str):
        """
        Initialize the log parser

        Args:
            file_path: Path to the CSV or Excel file

        Raises:
            FileNotFoundError: If file doesn't exist
        """

        self.file_path = Path(file_path)

        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        logger.info(f"Initializing LogParser with file: {file_path}")

        self.df = None
        self.destination_ips = set()

    def parse(self) -> pd.DataFrame:
        """
        Parse CSV or Excel file.
        """

        try:

            extension = self.file_path.suffix.lower()

            # --------------------------------------------------
            # CSV
            # --------------------------------------------------

            if extension == ".csv":

                encodings = [
                    "utf-8",
                    "utf-8-sig",
                    "cp1252",
                    "latin1"
                ]

                for enc in encodings:
                    try:
                        self.df = pd.read_csv(
                            self.file_path,
                            encoding=enc
                        )

                        logger.info(
                            f"CSV loaded successfully using encoding: {enc}"
                        )
                        break

                    except UnicodeDecodeError:
                        continue

                if self.df is None:
                    raise ValueError(
                        "Unable to read CSV. Unsupported encoding."
                    )

            # --------------------------------------------------
            # Excel
            # --------------------------------------------------

            elif extension in [".xlsx", ".xls"]:

                with pd.ExcelFile(
                    self.file_path,
                    engine="openpyxl"
                ) as excel:

                    sheet = (
                        "Raw"
                        if "Raw" in excel.sheet_names
                        else excel.sheet_names[0]
                    )

                    self.df = pd.read_excel(
                        excel,
                        sheet_name=sheet,
                        engine="openpyxl"
                    )

                logger.info(
                    f"Excel loaded successfully. Sheet: {sheet}"
                )

            else:
                raise ValueError(
                    "Unsupported file type. Please upload CSV, XLSX or XLS."
                )

            # Break any internal reference to workbook
            self.df = self.df.copy()

            logger.info(
                f"Successfully loaded {len(self.df)} records."
            )

            # --------------------------------------------------
            # Validate Required Columns
            # --------------------------------------------------

            required_columns = [
                "Source IP",
                "Destination IP"
            ]

            port_columns = [
                "Port",
                "Destination Port"
            ]

            missing_columns = [
                col
                for col in required_columns
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

            # Normalize Port column
            if (
                "Destination Port" in self.df.columns
                and "Port" not in self.df.columns
            ):
                self.df["Port"] = self.df["Destination Port"]

            return self.df

        except Exception as e:
            logger.exception("Failed to parse log file.")
            raise

    def extract_destination_ips(self) -> Set[str]:

        if self.df is None:
            raise RuntimeError(
                "Must call parse() before extracting IPs"
            )

        self.destination_ips = set(
            self.df["Destination IP"].dropna().astype(str).str.strip()
        )

        self.destination_ips = {
            ip
            for ip in self.destination_ips
            if ip
        }

        logger.info(
            f"Extracted {len(self.destination_ips)} unique destination IPs"
        )

        return self.destination_ips

    def categorize_communication(self):

        if self.df is None:
            raise RuntimeError(
                "Must call parse() before categorizing communication"
            )

        COMMON_PORTS = {
            20: "FTP Data",
            21: "FTP Control",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            67: "DHCP",
            68: "DHCP",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL",
            8080: "HTTP-Alt",
            27017: "MongoDB",
        }

        def get_service(port):
            try:
                return COMMON_PORTS.get(int(port), "Other")
            except Exception:
                return "Other"

        if "Destination Port" in self.df.columns:
            self.df["Service"] = self.df["Destination Port"].apply(get_service)
        else:
            self.df["Service"] = self.df["Port"].apply(get_service)

        if "Connection Type" in self.df.columns:
            self.df["Communication Type"] = (
                self.df["Connection Type"].astype(str)
                + " - "
                + self.df["Service"]
            )
        else:
            self.df["Communication Type"] = self.df["Service"]

        logger.info("Communication categories generated.")

    def validate_ip(self, ip: str) -> bool:

        try:

            parts = ip.split(".")

            if len(parts) != 4:
                return False

            return all(
                0 <= int(part) <= 255
                for part in parts
            )

        except Exception:
            return False

    def get_logs_by_ip(self, ip: str) -> pd.DataFrame:

        if self.df is None:
            raise RuntimeError(
                "Must call parse() before querying logs"
            )

        return self.df[
            self.df["Destination IP"] == ip
        ]