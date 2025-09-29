import os
import time
import json
from datetime import datetime, timedelta
from virustotal_python import Virustotal
import logging

class VirusTotalIntegration:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get('VT_API_KEY')
        self.vtotal = None
        self.last_request_time = 0
        self.request_count = 0
        self.daily_count = 0
        self.daily_reset_time = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Rate limiting (Free API: 4 requests/minute, 500/day)
        self.rate_limit_per_minute = 4
        self.rate_limit_per_day = 500
        self.min_request_interval = 15  # 15 seconds between requests for safety
        
        self.logger = self.setup_logging()
        
        if self.api_key:
            try:
                self.vtotal = Virustotal(API_KEY=self.api_key)
                self.logger.info("VirusTotal API initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize VirusTotal API: {e}")
    
    def setup_logging(self):
        logger = logging.getLogger('VirusTotalIntegration')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.FileHandler('logs/virustotal.log')
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def check_rate_limits(self):
        """Check if we can make a request within rate limits"""
        now = datetime.now()
        
        # Reset daily counter if it's a new day
        if now >= self.daily_reset_time + timedelta(days=1):
            self.daily_count = 0
            self.daily_reset_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Check daily limit
        if self.daily_count >= self.rate_limit_per_day:
            return False, "Daily API limit reached (500 requests)"
        
        # Check time since last request
        time_since_last = time.time() - self.last_request_time
        if time_since_last < self.min_request_interval:
            return False, f"Rate limit: wait {self.min_request_interval - time_since_last:.1f} seconds"
        
        return True, "OK"
    
    def wait_for_rate_limit(self):
        """Wait if necessary to respect rate limits"""
        can_request, message = self.check_rate_limits()
        if not can_request and "wait" in message:
            wait_time = float(message.split()[-2])
            time.sleep(wait_time)
    
    def check_file_hash(self, file_hash):
        """Check a file hash against VirusTotal"""
        if not self.vtotal:
            return None, "VirusTotal API not initialized"
        
        can_request, message = self.check_rate_limits()
        if not can_request:
            return None, message
        
        try:
            self.wait_for_rate_limit()
            
            resp = self.vtotal.request(f"files/{file_hash}")
            self.last_request_time = time.time()
            self.request_count += 1
            self.daily_count += 1
            
            if resp.status_code == 200:
                data = resp.json()["data"]
                stats = data["attributes"]["last_analysis_stats"]
                scan_date = data["attributes"].get("last_analysis_date", "Unknown")
                
                result = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0),
                    'total_scans': sum(stats.values()),
                    'scan_date': scan_date,
                    'permalink': f"https://www.virustotal.com/gui/file/{file_hash}",
                    'status': 'found'
                }
                
                self.logger.info(f"VirusTotal scan result for {file_hash}: {stats.get('malicious', 0)} malicious")
                return result, "Success"
                
            elif resp.status_code == 404:
                return {'status': 'not_found'}, "File not found in VirusTotal database"
            else:
                return None, f"VirusTotal API error: {resp.status_code}"
                
        except Exception as e:
            self.logger.error(f"VirusTotal API request failed: {e}")
            return None, f"Request failed: {str(e)}"
    
    def get_api_quota_status(self):
        """Get current API usage status"""
        return {
            'daily_count': self.daily_count,
            'daily_limit': self.rate_limit_per_day,
            'requests_remaining': self.rate_limit_per_day - self.daily_count,
            'last_request': self.last_request_time
        }

# Global instance
vt_integration = VirusTotalIntegration()

def check_file_hash_vt(file_hash):
    """Convenience function for checking file hashes"""
    return vt_integration.check_file_hash(file_hash)

def set_vt_api_key(api_key):
    """Set VirusTotal API key"""
    global vt_integration
    vt_integration = VirusTotalIntegration(api_key)
    return vt_integration.vtotal is not None
