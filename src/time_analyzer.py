"""
Time-Based Analysis Module
Analyzes temporal patterns in network traffic
"""

import pandas as pd
import logging
from typing import Dict, List, Any
from datetime import datetime
import numpy as np

logger = logging.getLogger(__name__)


class TimeBasedAnalyzer:
    """Analyzes time-based patterns in network traffic"""
    
    def __init__(self, df: pd.DataFrame):
        """
        Initialize time-based analyzer
        
        Args:
            df: DataFrame with timestamp column
        """
        self.df = df
        self._prepare_timestamps()
    
    def _prepare_timestamps(self):
        """Prepare timestamp data"""
        if 'Date' in self.df.columns and 'timestamp' not in self.df.columns:
            self.df['timestamp'] = pd.to_datetime(self.df['Date'], errors='coerce')
        
        if 'timestamp' in self.df.columns:
            self.df['hour'] = self.df['timestamp'].dt.hour
            self.df['day'] = self.df['timestamp'].dt.day
            self.df['minute'] = self.df['timestamp'].dt.minute
    
    def analyze_temporal_patterns(self) -> Dict[str, Any]:
        """Analyze all temporal patterns"""
        logger.info("Analyzing temporal patterns")
        
        results = {
            'hourly_distribution': self._get_hourly_distribution(),
            'peak_activity_periods': self._find_peak_periods(),
            'activity_spikes': self._detect_activity_spikes(),
            'activity_windows': self._analyze_activity_windows(),
        }
        
        results['findings'] = self._generate_temporal_findings(results)
        
        return results
    
    def _get_hourly_distribution(self) -> Dict[int, int]:
        """Get traffic distribution by hour"""
        if 'hour' not in self.df.columns:
            return {}
        
        hourly = self.df['hour'].value_counts().sort_index().to_dict()
        return hourly
    
    def _find_peak_periods(self) -> Dict[str, Any]:
        """Find peak activity periods"""
        if 'hour' not in self.df.columns:
            return {}
        
        hourly_counts = self.df['hour'].value_counts()
        
        if len(hourly_counts) == 0:
            return {}
        
        mean_traffic = hourly_counts.mean()
        std_traffic = hourly_counts.std()
        
        peak_hours = []
        for hour, count in hourly_counts.items():
            if count > mean_traffic + std_traffic:
                peak_hours.append({'hour': hour, 'traffic': count})
        
        peak_hours.sort(key=lambda x: x['traffic'], reverse=True)
        
        return {
            'peak_hours': peak_hours[:5],
            'mean_hourly_traffic': round(mean_traffic, 2),
            'std_hourly_traffic': round(std_traffic, 2),
        }
    
    def _detect_activity_spikes(self) -> List[Dict]:
        """Detect sudden traffic spikes"""
        if 'timestamp' not in self.df.columns:
            return []
        
        # Sort by timestamp
        df_sorted = self.df.sort_values('timestamp').copy()
        
        # Group by minute
        if pd.isna(df_sorted['timestamp']).any():
            return []
        
        try:
            minute_traffic = df_sorted.groupby(
                df_sorted['timestamp'].dt.floor('1min')
            ).size()
            
            # Calculate statistics
            mean_traffic = minute_traffic.mean()
            std_traffic = minute_traffic.std()
            spike_threshold = mean_traffic + (2 * std_traffic)
            
            spikes = []
            for timestamp, count in minute_traffic.items():
                if count > spike_threshold:
                    spikes.append({
                        'timestamp': str(timestamp),
                        'traffic_count': int(count),
                        'above_normal': int(count - mean_traffic),
                    })
            
            return sorted(spikes, key=lambda x: x['traffic_count'], reverse=True)[:10]
        
        except Exception as e:
            logger.error(f"Error detecting activity spikes: {e}")
            return []
    
    def _analyze_activity_windows(self) -> Dict[str, Any]:
        """Analyze suspicious activity windows"""
        results = {
            'business_hours': self._analyze_business_hours(),
            'off_hours': self._analyze_off_hours(),
            'weekend_activity': self._analyze_weekend_activity(),
        }
        
        return results
    
    def _analyze_business_hours(self) -> Dict[str, Any]:
        """Analyze traffic during business hours (9-17)"""
        if 'hour' not in self.df.columns:
            return {}
        
        business_hours = self.df[(self.df['hour'] >= 9) & (self.df['hour'] <= 17)]
        
        return {
            'count': len(business_hours),
            'percentage': round(len(business_hours) / len(self.df) * 100, 2) if len(self.df) > 0 else 0,
        }
    
    def _analyze_off_hours(self) -> Dict[str, Any]:
        """Analyze traffic during off-hours (17-9)"""
        if 'hour' not in self.df.columns:
            return {}
        
        off_hours = self.df[(self.df['hour'] < 9) | (self.df['hour'] >= 17)]
        
        return {
            'count': len(off_hours),
            'percentage': round(len(off_hours) / len(self.df) * 100, 2) if len(self.df) > 0 else 0,
            'risk_assessment': 'HIGH' if len(off_hours) / len(self.df) > 0.3 else 'LOW'
        }
    
    def _analyze_weekend_activity(self) -> Dict[str, Any]:
        """Analyze traffic on weekends"""
        if 'timestamp' not in self.df.columns:
            return {}
        
        try:
            weekend_mask = self.df['timestamp'].dt.dayofweek >= 5  # Saturday=5, Sunday=6
            weekend_traffic = self.df[weekend_mask]
            
            return {
                'count': len(weekend_traffic),
                'percentage': round(len(weekend_traffic) / len(self.df) * 100, 2) if len(self.df) > 0 else 0,
                'risk_assessment': 'HIGH' if len(weekend_traffic) > 0 else 'NONE'
            }
        except Exception as e:
            logger.error(f"Error analyzing weekend activity: {e}")
            return {}
    
    def _generate_temporal_findings(self, results: Dict) -> List[str]:
        """Generate temporal analysis findings"""
        findings = []
        
        hourly = results.get('hourly_distribution', {})
        if hourly:
            findings.append(f"Traffic detected across {len(hourly)} hours of the day")
        
        peaks = results.get('peak_activity_periods', {})
        if peaks.get('peak_hours'):
            peak_hour = peaks['peak_hours'][0]['hour']
            findings.append(f"Peak activity during hour {peak_hour}:00")
        
        spikes = results.get('activity_spikes', [])
        if spikes:
            findings.append(f"MEDIUM: {len(spikes)} activity spikes detected (above normal traffic)")
        
        windows = results.get('activity_windows', {})
        off_hours = windows.get('off_hours', {})
        if off_hours.get('percentage', 0) > 30:
            findings.append(f"SUSPICIOUS: {off_hours['percentage']}% of activity during off-hours (17:00-09:00)")
        
        weekend = windows.get('weekend_activity', {})
        if weekend.get('percentage', 0) > 0:
            findings.append(f"Weekend activity detected ({weekend['percentage']}%)")
        
        return findings
    
    def get_timeline_summary(self) -> Dict[str, Any]:
        """Generate timeline summary"""
        if 'timestamp' not in self.df.columns:
            return {'error': 'No timestamp data available'}
        
        valid_timestamps = self.df['timestamp'].dropna()
        
        if len(valid_timestamps) == 0:
            return {'error': 'No valid timestamps'}
        
        return {
            'first_activity': str(valid_timestamps.min()),
            'last_activity': str(valid_timestamps.max()),
            'duration': str(valid_timestamps.max() - valid_timestamps.min()),
            'total_events': len(self.df),
        }
