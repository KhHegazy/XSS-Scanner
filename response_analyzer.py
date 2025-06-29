from bs4 import BeautifulSoup
import re
from colorama import Fore, Style

class ResponseAnalyzer:
    def __init__(self):
        self.dom_sinks = [
            'document.write',
            'document.writeln',
            'innerHTML',
            'outerHTML',
            'insertAdjacentHTML',
            'eval',
            'setTimeout',
            'setInterval',
            'Function',
            'execScript'
        ]
        
        self.contexts = [
            'html',
            'attribute',
            'javascript',
            'url',
            'css',
            'xml',
            'json',
            'markdown'
        ]
        
        self.encodings = [
            'none',
            'url',
            'html',
            'js',
            'unicode',
            'base64',
            'hex',
            'octal'
        ]

    def analyze_response(self, response, payload):
        """Analyze response for XSS vulnerability"""
        result = {
            'vulnerable': False,
            'context': 'unknown',
            'risk_level': 'Low',
            'reflection_type': 'none',
            'dom_sink': 'none',
            'encoding': 'none',
            'filters_bypassed': [],
            'context_escape': False
        }
        
        # Check if payload is reflected in response
        if payload in response.text:
            result['vulnerable'] = True
            result['reflection_type'] = 'direct'
            
            # Analyze context
            result['context'] = self._determine_context(response.text, payload)
            
            # Check for DOM sinks
            dom_sink = self._find_dom_sink(response.text)
            if dom_sink:
                result['dom_sink'] = dom_sink
                result['risk_level'] = 'High'
            
            # Check for context escape
            if self._check_context_escape(response.text, payload):
                result['context_escape'] = True
                result['risk_level'] = 'Critical'
            
            # Check for encoding
            result['encoding'] = self._determine_encoding(response.text, payload)
            
            # Check for filter bypasses
            result['filters_bypassed'] = self._check_filter_bypasses(response.text, payload)
            
        return result
    
    def _determine_context(self, response_text, payload):
        """Determine the context where the payload is reflected"""
        soup = BeautifulSoup(response_text, 'html.parser')
        
        # Check HTML context
        if f'>{payload}<' in response_text:
            return 'html'
            
        # Check attribute context
        if f'="{payload}"' in response_text:
            return 'attribute'
            
        # Check JavaScript context
        if f'var x = "{payload}"' in response_text or f'var x = \'{payload}\'' in response_text:
            return 'javascript'
            
        # Check URL context
        if f'href="{payload}"' in response_text or f'src="{payload}"' in response_text:
            return 'url'
            
        # Check CSS context
        if f'style="{payload}"' in response_text:
            return 'css'
            
        # Check XML context
        if f'<tag>{payload}</tag>' in response_text:
            return 'xml'
            
        # Check JSON context
        if f'{{"key":"{payload}"}}' in response_text:
            return 'json'
            
        # Check Markdown context
        if f'[{payload}]' in response_text:
            return 'markdown'
            
        return 'unknown'
    
    def _find_dom_sink(self, response_text):
        """Find DOM-based XSS sinks in the response"""
        for sink in self.dom_sinks:
            if sink in response_text:
                return sink
        return None
    
    def _check_context_escape(self, response_text, payload):
        """Check if the payload can escape its context"""
        # Check for script tag injection
        if '<script>' in payload and '</script>' in payload:
            return True
            
        # Check for event handler injection
        if 'on' in payload.lower() and '=' in payload:
            return True
            
        # Check for URL scheme injection
        if 'javascript:' in payload.lower():
            return True
            
        return False
    
    def _determine_encoding(self, response_text, payload):
        """Determine the encoding of the reflected payload"""
        # Check for URL encoding
        if '%' in payload and all(c in '0123456789ABCDEFabcdef%' for c in payload):
            return 'url'
            
        # Check for HTML encoding
        if '&' in payload and ';' in payload:
            return 'html'
            
        # Check for JavaScript encoding
        if '\\u' in payload or '\\x' in payload:
            return 'js'
            
        # Check for Unicode encoding
        if '\\u' in payload:
            return 'unicode'
            
        # Check for Base64 encoding
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', payload):
            return 'base64'
            
        # Check for Hex encoding
        if re.match(r'^[0-9a-fA-F]+$', payload):
            return 'hex'
            
        # Check for Octal encoding
        if re.match(r'^[0-7]+$', payload):
            return 'octal'
            
        return 'none'
    
    def _check_filter_bypasses(self, response_text, payload):
        """Check for common filter bypasses"""
        bypasses = []
        
        # Check for case variation
        if payload.lower() != payload and payload.upper() != payload:
            bypasses.append('case_variation')
            
        # Check for whitespace variation
        if '\t' in payload or '\n' in payload or '\r' in payload:
            bypasses.append('whitespace')
            
        # Check for comment injection
        if '<!--' in payload or '/*' in payload:
            bypasses.append('comments')
            
        # Check for null byte injection
        if '\0' in payload:
            bypasses.append('null_bytes')
            
        # Check for encoding
        if self._determine_encoding(response_text, payload) != 'none':
            bypasses.append('encoding')
            
        return bypasses
    
    def print_analysis(self, results, url):
        """Print detailed analysis results"""
        print(f"\n{Fore.CYAN}=== XSS Analysis for {url} ==={Style.RESET_ALL}")
        
        if results['vulnerable']:
            print(f"{Fore.YELLOW}[!] XSS Vulnerability Detected{Style.RESET_ALL}")
            if results['context']:
                print(f"Context: {results['context']}")
                
        if results['dom_sink']:
            print(f"{Fore.RED}[!] DOM-based XSS Vulnerability Detected{Style.RESET_ALL}")
            
        if results['context_escape']:
            print(f"{Fore.RED}[!] Context Escape Detected{Style.RESET_ALL}")
            
        if results['encoding']:
            print(f"Encoding: {results['encoding']}")
            
        if results['filters_bypassed']:
            print(f"Filters Bypassed: {', '.join(results['filters_bypassed'])}")
            
        print(f"Risk Level: {results['risk_level']}")
        
    def get_risk_recommendations(self, results):
        """Get security recommendations based on findings"""
        recommendations = []
        
        if results['vulnerable']:
            recommendations.extend([
                "Implement proper input validation",
                "Use context-aware output encoding",
                "Consider implementing Content Security Policy (CSP)"
            ])
            
        if results['dom_sink']:
            recommendations.extend([
                "Avoid using dangerous DOM manipulation methods",
                "Sanitize data before using in DOM operations",
                "Use safe DOM APIs like textContent instead of innerHTML"
            ])
            
        if results['context_escape']:
            recommendations.extend([
                "Avoid using context-sensitive data in URLs",
                "Use safe APIs for URL manipulation",
                "Consider implementing URL validation"
            ])
            
        if results['encoding']:
            recommendations.extend([
                "Use safe encoding methods",
                "Consider implementing Content Security Policy (CSP)"
            ])
            
        if results['filters_bypassed']:
            recommendations.extend([
                "Avoid using common filter bypasses",
                "Consider implementing stronger filtering mechanisms"
            ])
            
        return recommendations
