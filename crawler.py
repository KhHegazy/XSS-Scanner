import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import threading
from queue import Queue
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import threading
from colorama import Fore, Style
import re
from collections import deque

class WebCrawler:
    def __init__(self, base_url, max_depth=3, max_urls=100, threads=10, verify_ssl=True, timeout=30):
        # Initialize session with retry strategy
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.timeout = timeout
        
        # Add common user-agents for better coverage
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) Safari/604.1',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
        ]
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Basic parameters
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.threads = threads
        
        # Thread-safe collections
        self.visited_urls = set()
        self.urls_to_visit = deque([(base_url, 0)])  # (url, depth)
        self.forms_found = []
        self.parameters_found = set()
        self.lock = threading.Lock()
        
        # Security findings and form tracking
        self.security_findings = []
        self.seen_forms = set()
        
        # Interesting parameters that might be vulnerable
        self.interesting_params = {'id', 'page', 'search', 'q', 'query', 'file', 'redirect', 'url', 'path', 'return_url'}
        
    def is_valid_url(self, url):
        """Enhanced URL validation with security checks"""
        if not url:
            return False
            
        parsed = urlparse(url)
        
        # Basic validation
        if not parsed.scheme or not parsed.netloc:
            return False
            
        # Security checks
        if parsed.scheme not in ['http', 'https']:
            return False
            
        # Domain validation
        if parsed.netloc != self.base_domain:
            # Allow subdomains if they match the base domain
            if not self.base_domain in parsed.netloc:
                return False
                
        # File extension check
        ignored_extensions = {
            # Static files
            '.css', '.js', '.map', '.woff', '.woff2', '.ttf', '.eot',
            # Images
            '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.webp',
            # Documents
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz',
            # Media
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv'
        }
        if any(url.lower().endswith(ext) for ext in ignored_extensions):
            return False
            
        # Check for potential infinite loops
        path = parsed.path.lower()
        dangerous_patterns = [
            'logout', 'signout', 'delete', 'remove',
            '/\\d+/\\d+/\\d+',  # Calendar-like paths
            '/../', '/..'
        ]
        if any(pattern in path for pattern in dangerous_patterns):
            return False
            
        return True
        
    def extract_urls(self, html, current_url):
        """Enhanced URL extraction with JavaScript parsing"""
        soup = BeautifulSoup(html, 'html.parser')
        urls = set()
        
        # HTML elements that might contain URLs
        url_attributes = {
            'a': ['href'],
            'form': ['action'],
            'img': ['src', 'data-src', 'srcset'],
            'script': ['src'],
            'link': ['href'],
            'iframe': ['src'],
            'frame': ['src'],
            'embed': ['src'],
            'object': ['data'],
            'source': ['src', 'srcset'],
            'video': ['src', 'poster'],
            'audio': ['src'],
            'track': ['src'],
            'input': ['src'],  # For input type="image"
            'area': ['href'],
            'base': ['href'],
            'meta': ['content']  # For refresh/redirect
        }
        
        # Extract URLs from elements
        for tag in soup.find_all():
            if tag.name in url_attributes:
                for attr in url_attributes[tag.name]:
                    url = tag.get(attr)
                    if url:
                        # Handle srcset attribute
                        if attr == 'srcset':
                            urls_in_srcset = re.findall(r'([^\s,]+)', url)
                            for srcset_url in urls_in_srcset:
                                full_url = urljoin(current_url, srcset_url.split()[0])
                                if self.is_valid_url(full_url):
                                    urls.add(full_url)
                        else:
                            full_url = urljoin(current_url, url)
                            if self.is_valid_url(full_url):
                                urls.add(full_url)
        
        # Extract URLs from inline styles
        for tag in soup.find_all(style=True):
            style_urls = re.findall(r'url\(["\']?([^\)"\'])["\']?\)', tag['style'])
            for url in style_urls:
                full_url = urljoin(current_url, url)
                if self.is_valid_url(full_url):
                    urls.add(full_url)
        
        # Extract URLs from style tags
        for style in soup.find_all('style'):
            if style.string:
                style_urls = re.findall(r'url\(["\']?([^\)"\'])["\']?\)', style.string)
                for url in style_urls:
                    full_url = urljoin(current_url, url)
                    if self.is_valid_url(full_url):
                        urls.add(full_url)
        
        # Enhanced JavaScript URL extraction
        js_patterns = [
            # Common AJAX patterns
            r'(?:fetch|axios|\$\.(?:get|post|ajax))\s*\(["\']([^"\')]+)["\']',
            # URL assignments
            r'(?:url|href|src)\s*=\s*["\']([^"\')]+)["\']',
            # Template literals
            r'`[^`]*?(?:https?://|/)[^`]+`',
            # Common frontend router patterns
            r'(?:router\.push|router\.replace|navigate)\s*\(["\']([^"\')]+)["\']',
            # API endpoints
            r'api\.["\']([^"\')]+)["\']',
            # Hardcoded URLs
            r'["\'](?:https?://|/)[^"\')]+["\']'
        ]
        
        for script in soup.find_all('script'):
            if script.string:
                for pattern in js_patterns:
                    matches = re.findall(pattern, script.string)
                    for match in matches:
                        # Clean up the match
                        url = match.strip('"\'')
                        if url:
                            full_url = urljoin(current_url, url)
                            if self.is_valid_url(full_url):
                                urls.add(full_url)
        
        # Extract from data-* attributes that might contain URLs
        for tag in soup.find_all(attrs=lambda x: any(k.startswith('data-') for k in x.keys())):
            for attr, value in tag.attrs.items():
                if attr.startswith('data-') and isinstance(value, str):
                    # Look for URL patterns in data attributes
                    url_matches = re.findall(r'(?:https?://|/)[^\s"\'>]+', value)
                    for url in url_matches:
                        full_url = urljoin(current_url, url)
                        if self.is_valid_url(full_url):
                            urls.add(full_url)
        
        return urls
        
    def extract_forms(self, html, url):
        """Enhanced form extraction with advanced input handling"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                'inputs': [],
                'javascript_events': [],
                'csrf_token': None
            }
            
            # Extract form-level JavaScript events
            js_events = [attr for attr in form.attrs if attr.startswith('on')]
            form_data['javascript_events'] = js_events
            
            # Get all input fields with enhanced attributes
            for input_field in form.find_all(['input', 'textarea', 'select', 'button']):
                input_data = {
                    'name': input_field.get('name', ''),
                    'type': input_field.get('type', 'text'),
                    'value': input_field.get('value', ''),
                    'required': input_field.has_attr('required'),
                    'id': input_field.get('id', ''),
                    'class': input_field.get('class', []),
                    'max_length': input_field.get('maxlength'),
                    'pattern': input_field.get('pattern'),
                    'placeholder': input_field.get('placeholder'),
                    'readonly': input_field.has_attr('readonly'),
                    'disabled': input_field.has_attr('disabled'),
                    'autocomplete': input_field.get('autocomplete'),
                    'js_events': [attr for attr in input_field.attrs if attr.startswith('on')]
                }
                
                # Special handling for select elements
                if input_field.name == 'select':
                    input_data['options'] = [
                        {
                            'value': option.get('value', ''),
                            'text': option.text.strip(),
                            'selected': option.has_attr('selected')
                        }
                        for option in input_field.find_all('option')
                    ]
                
                # Look for potential CSRF tokens
                name_lower = input_data['name'].lower()
                if any(token in name_lower for token in ['csrf', 'token', 'nonce']):
                    form_data['csrf_token'] = input_data['value']
                
                form_data['inputs'].append(input_data)
                
            # Additional form metadata
            form_data['has_file_upload'] = any(
                input_['type'] == 'file' for input_ in form_data['inputs']
            )
            form_data['has_password'] = any(
                input_['type'] == 'password' for input_ in form_data['inputs']
            )
            
            forms.append(form_data)
            
        return forms
        
    def extract_parameters(self, url):
        """Extract URL parameters that might be vulnerable"""
        parsed = urlparse(url)
        params = {}
        
        # Get parameters from query string
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key = param.split('=')[0]
                    params[key] = True
        
        return params
        
    def _process_url(self, url, depth):
        """Process a URL and extract links and forms"""
        if depth > self.max_depth or len(self.visited_urls) >= self.max_urls:
            return
        
        if url in self.visited_urls:
            return
            
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url, verify=False, timeout=self.timeout)
            if response.status_code != 200:
                return
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract links
            links = soup.find_all('a')
            for link in links:
                href = link.get('href')
                if href:
                    try:
                        absolute_url = urljoin(url, href)
                        if self.is_valid_url(absolute_url):
                            self._process_url(absolute_url, depth + 1)
                    except Exception:
                        continue
                    
            # Extract parameters from URL
            params = self.extract_parameters(url)
            if params:
                self.parameters_found.update(params.keys())
                print(f"{Fore.GREEN}[+] Found parameters at: {url}{Style.RESET_ALL}")
                
            # Extract forms
            forms = self.extract_forms(response.text, url)
            for form in forms:
                # Check for duplicate forms
                form_hash = hash(str(form))
                if form_hash not in self.seen_forms:
                    self.forms_found.append(form)
                    self.seen_forms.add(form_hash)
                    
            # Analyze security headers
            security_headers = {
                'X-Frame-Options': response.headers.get('X-Frame-Options'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options')
            }
            
            if not security_headers['X-XSS-Protection']:
                print(f"{Fore.YELLOW}[!] Missing X-XSS-Protection header at: {url}{Style.RESET_ALL}")
                
            # Store security findings
            self.security_findings.append({
                'url': url,
                'headers': security_headers,
                'vulnerabilities': []
            })
            
            # Print progress with more details
            print(f"\n{Fore.CYAN}[*] Crawled: {url}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Depth: {depth}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Forms: {len(forms)} new, {len(self.forms_found)} total{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Parameters: {len(params)} new, {len(self.parameters_found)} total{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error crawling {url}: {str(e)}{Style.RESET_ALL}")


    def crawl(self):
        """Start the crawler"""
        print(f"{Fore.CYAN}[*] Starting crawler on {self.base_url}")
        print(f"{Fore.CYAN}[*] Max depth: {self.max_depth}, Max URLs: {self.max_urls}{Style.RESET_ALL}")
        
        try:
            # Initialize session with retry strategy
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[500, 502, 503, 504, 429]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount('http://', adapter)
            self.session.mount('https://', adapter)
            
            # Get initial page
            response = self.session.get(self.base_url, verify=False, timeout=self.timeout)
            if response.status_code == 200:
                self._process_url(self.base_url, 0)
            else:
                print(f"{Fore.RED}[-] Error: Initial request failed with status code {response.status_code}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error crawling {self.base_url}: {str(e)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Crawling completed:")
        print(f"[+] Total URLs crawled: {len(self.visited_urls)}")
        print(f"[+] Total forms found: {len(self.forms_found)}")
        print(f"[+] Total parameters found: {len(self.parameters_found)}{Style.RESET_ALL}")
        
        return {
            'urls': list(self.visited_urls),
            'forms': self.forms_found,
            'parameters': list(self.parameters_found)
        }



