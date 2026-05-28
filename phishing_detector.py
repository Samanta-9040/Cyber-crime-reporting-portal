"""
Phishing URL Detector Module
Analyzes URLs for phishing indicators
"""

import re
import urllib.parse
from typing import Dict, List, Tuple

class PhishingDetector:
    """Detects potential phishing URLs using multiple heuristics"""
    
    # Common phishing patterns
    SUSPICIOUS_PATTERNS = {
        'url_shorteners': ['bit.ly', 'tinyurl.com', 'ow.ly', 'goo.gl', 'short.link'],
        'suspicious_domains': ['paypal-verify', 'amazon-login', 'apple-id', 'verify-account'],
        'suspicious_tlds': ['.tk', '.ml', '.ga', '.cf'],  # Free TLDs often used in phishing
    }
    
    def __init__(self):
        self.risk_score = 0
        self.flags = []
    
    def analyze_url(self, url: str) -> Dict:
        """
        Analyze a URL for phishing indicators
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary with analysis results
        """
        self.risk_score = 0
        self.flags = []
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
            
            # Check 1: URL shorteners
            self._check_url_shorteners(domain)
            
            # Check 2: Suspicious domain patterns
            self._check_suspicious_domains(domain)
            
            # Check 3: TLD analysis
            self._check_suspicious_tlds(domain)
            
            # Check 4: HTTPS check
            self._check_https(parsed_url.scheme)
            
            # Check 5: Suspicious keywords in URL
            self._check_suspicious_keywords(domain, path)
            
            # Check 6: IP address instead of domain
            self._check_ip_address(domain)
            
            # Check 7: Homograph attacks (Unicode/similar characters)
            self._check_homograph_attacks(domain)
            
            # Determine risk level
            risk_level = self._calculate_risk_level()
            
            return {
                'url': url,
                'is_phishing': risk_level in ['HIGH', 'CRITICAL'],
                'risk_level': risk_level,
                'risk_score': self.risk_score,
                'flags': self.flags,
                'recommendation': self._get_recommendation(risk_level)
            }
            
        except Exception as e:
            return {
                'url': url,
                'is_phishing': False,
                'risk_level': 'UNKNOWN',
                'error': str(e)
            }
    
    def _check_url_shorteners(self, domain: str) -> None:
        """Check if URL uses shortener service"""
        for shortener in self.SUSPICIOUS_PATTERNS['url_shorteners']:
            if shortener in domain:
                self.flags.append('Uses URL shortener service')
                self.risk_score += 15
    
    def _check_suspicious_domains(self, domain: str) -> None:
        """Check for suspicious domain patterns"""
        for pattern in self.SUSPICIOUS_PATTERNS['suspicious_domains']:
            if pattern in domain:
                self.flags.append(f'Suspicious domain pattern: {pattern}')
                self.risk_score += 20
    
    def _check_suspicious_tlds(self, domain: str) -> None:
        """Check for suspicious TLDs"""
        for tld in self.SUSPICIOUS_PATTERNS['suspicious_tlds']:
            if domain.endswith(tld):
                self.flags.append(f'Uses suspicious TLD: {tld}')
                self.risk_score += 10
    
    def _check_https(self, scheme: str) -> None:
        """Check if using HTTPS"""
        if scheme != 'https':
            self.flags.append('Not using HTTPS encryption')
            self.risk_score += 10
    
    def _check_suspicious_keywords(self, domain: str, path: str) -> None:
        """Check for suspicious keywords"""
        suspicious_keywords = ['verify', 'confirm', 'login', 'update-password', 'validate',
                             'secure', 'account', 'paypal', 'amazon', 'apple', 'google']
        
        combined = f"{domain}/{path}"
        for keyword in suspicious_keywords:
            if keyword in combined:
                self.flags.append(f'Contains suspicious keyword: {keyword}')
                self.risk_score += 5
    
    def _check_ip_address(self, domain: str) -> None:
        """Check if using IP address instead of domain"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, domain):
            self.flags.append('URL uses IP address instead of domain name')
            self.risk_score += 25
    
    def _check_homograph_attacks(self, domain: str) -> None:
        """Check for homograph attacks using similar characters"""
        # Common homograph substitutions
        homograph_pairs = [
            ('l', '1'), ('o', '0'), ('s', '5'), ('i', '1'),
            ('a', 'ɑ'), ('e', 'е')  # Cyrillic characters
        ]
        
        for suspicious_char in ['1', '0', '5', 'ɑ', 'е']:
            if suspicious_char in domain:
                self.flags.append('Possible homograph attack detected')
                self.risk_score += 15
                break
    
    def _calculate_risk_level(self) -> str:
        """Calculate risk level based on score"""
        if self.risk_score >= 60:
            return 'CRITICAL'
        elif self.risk_score >= 40:
            return 'HIGH'
        elif self.risk_score >= 20:
            return 'MEDIUM'
        elif self.risk_score > 0:
            return 'LOW'
        else:
            return 'SAFE'
    
    def _get_recommendation(self, risk_level: str) -> str:
        """Get user recommendation based on risk level"""
        recommendations = {
            'CRITICAL': 'DO NOT visit this URL. Report it immediately.',
            'HIGH': 'This URL appears suspicious. Avoid clicking unless you are certain.',
            'MEDIUM': 'Use caution with this URL. Verify the sender and destination.',
            'LOW': 'Minor risk indicators detected. Proceed with normal security practices.',
            'SAFE': 'URL appears safe based on analysis.',
            'UNKNOWN': 'Could not analyze URL. Please verify manually.'
        }
        return recommendations.get(risk_level, 'Unknown risk level')


def batch_analyze_urls(urls: List[str]) -> List[Dict]:
    """
    Analyze multiple URLs at once
    
    Args:
        urls: List of URLs to analyze
        
    Returns:
        List of analysis results
    """
    detector = PhishingDetector()
    results = []
    
    for url in urls:
        results.append(detector.analyze_url(url))
    
    return results
