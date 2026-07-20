import re
from urllib.parse import urlparse

class RuleEngine:
    # Common phishing keywords and patterns
    URGENT_KEYWORDS = [
        r'\burgent(ly)?\b', r'\bimmediate(ly)?\b', r'\baction required\b', 
        r'\bsuspend(ed)?\b', r'\brestrict(ed)?\b', r'\bunauthorized\b', 
        r'\bterminate(d)?\b', r'\bdeactivate(d)?\b', r'\bcompromise(d)?\b', 
        r'\bconsequence(s)?\b', r'\bact now\b', r'\bimportant alert\b',
        r'\bsecurity breach\b', r'\baccount block(ed)?\b', r'\bexpired?\b'
    ]
    
    CREDENTIAL_KEYWORDS = [
        r'\bpasswords?\b', r'\bpasscode\b', r'\botp\b', r'\bone-time password\b',
        r'\bverify\b', r'\bcredentials?\b', r'\bcredit card\b', r'\bsocial security\b',
        r'\bssn\b', r'\bpin number\b', r'\bsecurity code\b', r'\bcvv\b', 
        r'\blogin here\b', r'\bupdate payment\b', r'\bbilling details\b'
    ]
    
    BRAND_TYPOS = {
        'paypal': ['paypa1', 'pay-pal', 'paypal-support', 'paypaI'],
        'microsoft': ['microsofft', 'microsoft-security', 'micosoft', 'microsft'],
        'google': ['g00gle', 'gooogle', 'google-auth'],
        'netflix': ['netfl1x', 'netf1ix', 'netflix-billing'],
        'amazon': ['amz0n', 'amaz0n', 'amazon-security', 'ama-zon'],
        'apple': ['app1e', 'apple-support', 'apple-billing'],
        'chase': ['chase-bank', 'chase-security'],
        'wells fargo': ['wellsfargo-update', 'wells-fargo-security']
    }
    
    SUSPICIOUS_TLDS = [
        '.xyz', '.top', '.click', '.link', '.info', '.pw', '.cc', '.download', 
        '.online', '.club', '.stream', '.date', '.trade', '.support', '.security'
    ]
    
    @classmethod
    def analyze(cls, subject, body, sender=""):
        text = f"{subject}\n{body}".lower()
        sender = sender.lower()
        
        results = {
            'suspicious_urls': [],
            'urgent_language_count': 0,
            'urgent_matches': [],
            'credential_request_count': 0,
            'credential_matches': [],
            'brand_impersonation': [],
            'excessive_punctuation': False,
            'suspicious_sender': False,
            'score': 0,  # Accumulative threat score (out of 100)
            'warnings': []
        }
        
        # 1. URL Analysis
        # Regex to find URLs
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        urls = re.findall(url_pattern, text)
        
        for url in urls:
            # Normalize url for parsing
            parsed_url = url
            if not url.startswith('http'):
                parsed_url = 'http://' + url
                
            try:
                parsed = urlparse(parsed_url)
                domain = parsed.netloc.split(':')[0]
                
                # Check for IP address in domain
                ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
                if re.match(ip_pattern, domain):
                    msg = f"URL contains direct IP address: {url}"
                    results['suspicious_urls'].append(msg)
                    results['score'] += 25
                    results['warnings'].append("IP Address used in URL domain")
                    
                # Check for suspicious TLDs
                for tld in cls.SUSPICIOUS_TLDS:
                    if domain.endswith(tld):
                        msg = f"URL uses suspicious top-level domain ({tld}): {url}"
                        results['suspicious_urls'].append(msg)
                        results['score'] += 15
                        results['warnings'].append(f"Suspicious TLD ({tld}) used")
                        break
                        
                # Check for brand typos/spoofing in URL domain
                for brand, typos in cls.BRAND_TYPOS.items():
                    # If domain contains a typo or looks like brand but isn't the official domain
                    for typo in typos:
                        if typo in domain:
                            msg = f"Potential typosquatting or brand spoofing in URL: {url}"
                            results['suspicious_urls'].append(msg)
                            results['score'] += 20
                            results['brand_impersonation'].append(brand.capitalize())
                            results['warnings'].append(f"Brand Impersonation ({brand.capitalize()}) detected in URL")
                            break
                            
                # Check for HTTP instead of HTTPS on login/verify URLs
                if url.startswith('http://') and any(keyword in url.lower() for keyword in ['login', 'signin', 'verify', 'bank', 'secure', 'billing', 'update']):
                    msg = f"Insecure HTTP link for sensitive action: {url}"
                    results['suspicious_urls'].append(msg)
                    results['score'] += 10
                    results['warnings'].append("Insecure HTTP link found")
                    
                # Check for excessive subdomains
                subdomains = domain.split('.')
                if len(subdomains) > 4:
                    msg = f"URL contains excessive subdomains: {url}"
                    results['suspicious_urls'].append(msg)
                    results['score'] += 10
                    results['warnings'].append("Excessive subdomains in link")
                    
            except Exception:
                pass
                
        # 2. Urgent Language
        for pattern in cls.URGENT_KEYWORDS:
            matches = re.findall(pattern, text)
            if matches:
                results['urgent_language_count'] += len(matches)
                clean_match = pattern.replace(r'\b', '').replace('?', '')
                results['urgent_matches'].append(clean_match)
                results['score'] += 5 * len(matches)
                
        if results['urgent_language_count'] > 0:
            results['warnings'].append(f"Urgent/Coercive language detected ({results['urgent_language_count']} triggers)")
            
        # 3. Credential/OTP Requests
        for pattern in cls.CREDENTIAL_KEYWORDS:
            matches = re.findall(pattern, text)
            if matches:
                results['credential_request_count'] += len(matches)
                clean_match = pattern.replace(r'\b', '').replace('?', '')
                results['credential_matches'].append(clean_match)
                results['score'] += 8 * len(matches)
                
        if results['credential_request_count'] > 0:
            results['warnings'].append(f"Requests credentials, OTPs, or payment information")
            
        # 4. Brand Typos in Text
        for brand, typos in cls.BRAND_TYPOS.items():
            for typo in typos:
                if typo in text:
                    # Prevent duplicate brand warnings
                    brand_cap = brand.capitalize()
                    if brand_cap not in results['brand_impersonation']:
                        results['brand_impersonation'].append(brand_cap)
                        results['score'] += 15
                        results['warnings'].append(f"Suspicious brand spelling: '{typo}' instead of '{brand_cap}'")
                        break
                        
        # 5. Excessive Punctuation
        punc_patterns = [r'!{3,}', r'\${3,}', r'\?{3,}']
        for pat in punc_patterns:
            if re.search(pat, text):
                results['excessive_punctuation'] = True
                results['score'] += 5
                results['warnings'].append("Excessive punctuation (e.g. '!!!', '$$$')")
                break
                
        # 6. Suspicious Sender Domain
        if sender:
            # Check sender TLD
            for tld in cls.SUSPICIOUS_TLDS:
                if sender.endswith(tld):
                    results['suspicious_sender'] = True
                    results['score'] += 15
                    results['warnings'].append(f"Sender email uses suspicious top-level domain ({tld})")
                    break
            # Check brand mismatch in sender name vs domain
            # e.g. sender display name contains "PayPal Support" but email is "support@gmail-billing.xyz"
            display_name = ""
            email_address = sender
            if '<' in sender and '>' in sender:
                display_name = sender.split('<')[0].strip()
                email_address = sender.split('<')[1].split('>')[0].strip()
                
            if display_name:
                for brand in cls.BRAND_TYPOS.keys():
                    if brand in display_name.lower() and brand not in email_address.lower():
                        results['suspicious_sender'] = True
                        results['score'] += 20
                        results['warnings'].append(f"Sender display name spoofing: claims to be '{brand.capitalize()}' but email is '{email_address}'")
                        break
                        
        # Cap rules score at 100
        results['score'] = min(results['score'], 100)
        
        return results
