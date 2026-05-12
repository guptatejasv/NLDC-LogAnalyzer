"""
Communication Analyzer Module
Analyzes categorized communication types to provide insights.
"""

import pandas as pd
import logging
from collections import Counter
from typing import Dict, Any

logger = logging.getLogger(__name__)


class CommunicationAnalyzer:
    """Analyzes communication patterns from parsed logs."""

    def __init__(self, df: pd.DataFrame):
        """
        Initialize with the DataFrame containing parsed and categorized logs.

        Args:
            df: DataFrame with 'Communication Type' and 'Action' columns.
        """
        self.df = df
        self.analysis_results: Dict[str, Any] = {}
        logger.info("CommunicationAnalyzer initialized.")

    def analyze(self) -> Dict[str, Any]:
        """
        Perform a detailed analysis of communication types.

        Returns:
            A dictionary containing various communication analysis results.
        """
        if self.df.empty:
            logger.warning("DataFrame is empty, skipping communication analysis.")
            return {}

        logger.info("Starting communication analysis...")

        # Overall communication type frequency
        communication_counts = self.df['Communication Type'].value_counts().to_dict()
        self.analysis_results['overall_communication_counts'] = communication_counts
        logger.info(f"Overall communication counts: {communication_counts}")

        # Communication by action (allow/deny)
        communication_by_action = {}
        for comm_type in self.df['Communication Type'].unique():
            subset = self.df[self.df['Communication Type'] == comm_type]
            action_counts = subset['Action'].value_counts().to_dict()
            communication_by_action[comm_type] = action_counts
        self.analysis_results['communication_by_action'] = communication_by_action
        logger.info(f"Communication by action: {communication_by_action}")

        # Top 5 most frequent communication types
        top_5_comm_types = self.df['Communication Type'].value_counts().nlargest(5).to_dict()
        self.analysis_results['top_5_communication_types'] = top_5_comm_types
        logger.info(f"Top 5 communication types: {top_5_comm_types}")

        # Total unique communication types
        self.analysis_results['total_unique_communication_types'] = len(communication_counts)

        logger.info("Communication analysis complete.")
        return self.analysis_results

    def get_results(self) -> Dict[str, Any]:
        """
        Returns the stored analysis results.
        """
        return self.analysis_results
