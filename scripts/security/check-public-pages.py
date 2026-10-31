#!/usr/bin/env python3
"""Check public sibling links, executable inline CSP pins when present, and data boundaries."""
import base64
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.policies = []
        self.links = []
        self.executable = []
        self.active = None
        self.buffer = []

    def handle_starttag(self, tag, attributes):
        a = dict(attributes)
        if tag == 'meta' and a.get('http-equiv', '').lower() == 'content-security-policy':
            self.policies.append(a.get('content', ''))
        for name in ['href', 'src']:
            if a.get(name):
                self.links.append(a[name])
        if tag in ['script', 'style'] and not a.get('src'):
            if tag == 'script' and a.get('type', '') in ['application/json', 'application/ld+json']:
                return
            self.active = tag
            self.buffer = []
        if tag == 'form' and a.get('method', 'get').lower() != 'get':
            raise ValueError('A submission form requires privacy and server review.')

    def handle_data(self, data):
        if self.active:
            self.buffer.append(data)

    def handle_endtag(self, tag):
        if self.active == tag:
            self.executable.append((tag, ''.join(self.buffer)))
            self.active = None


def check(path):
    text = path.read_text(encoding='utf-8')
    if re.search('[\u2013\u2014]', text):
        raise ValueError('Review public long dash punctuation.')
    page = Page()
    page.feed(text)
    for link in page.links:
        u = urlsplit(link)
        if u.scheme or u.netloc or not u.path:
            continue
        target = (path.parent / unquote(u.path)).resolve()
        if not target.is_relative_to(ROOT) or not target.exists():
            raise ValueError('A local public destination is missing or outside the package.')
    for kind, block in page.executable:
        if kind == 'script' and re.search(r'\b(?:fetch|XMLHttpRequest|WebSocket|sendBeacon|localStorage|sessionStorage|indexedDB|eval)\s*[.(]|\bnew\s+Function\b', block):
            raise ValueError('A script data or execution boundary needs review.')
        pin = "'sha256-" + base64.b64encode(hashlib.sha256(block.encode()).digest()).decode() + "'"
        for policy in page.policies:
            directive = 'script-src' if kind == 'script' else 'style-src'
            value = next((part.strip() for part in policy.split(';') if part.strip().startswith(directive + ' ')), '')
            if pin not in value.split():
                raise ValueError('A present CSP is missing an exact inline block pin.')
    return len(page.policies)


if __name__ == '__main__':
    pages = [ROOT / name for name in ['everyday-helpers.html', 'small-start.html', 'kit-guide.html']]
    count = sum(check(p) for p in pages)
    print('Checked three public pages, local destinations and script boundaries.')
    print(f'Existing CSP policies with verified block pins: {count}. Missing policies remain a release review item.')
