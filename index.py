#!/usr/bin/env python3
"""
ULTIMATE PRO PHISHING ANALYZER - 100% COMPLETE FINAL VERSION
- Fixed: Dead domain (NXDOMAIN) now correctly flagged as CRITICAL threat
- Fixed: SSL hides raw socket errors, shows user-friendly messages
- Fixed: URLScan gracefully handles long URLs (falls back to domain search)
- Fixed: Scoring properly weights dead domains + VT URL detections
"""

import os, sys, subprocess, importlib, threading, time, json, re, ssl, socket, datetime, base64, warnings
from urllib.parse import urlparse
import requests
import whois
import dns.resolver
from flask import Flask, request, jsonify, send_file
from io import BytesIO

warnings.filterwarnings('ignore')

for pkg in ['flask', 'requests', 'python-whois', 'dnspython']:
    try: importlib.import_module(pkg.replace('-', '_'))
    except ImportError: subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "--quiet"])

app = Flask(__name__)
GOOGLE_KEY = "AIzaSyDF4jhxma9fJePs5NgwY3qGsdzali238sM0"
VT_KEY = "d7455b05fd4180085a026805906846d1ba089ddf7b1c2c6b9d418fffa6ab4ca40"
URLSCAN_KEY = "019fefb7-4cf9-74ad-9851-e6fefbf6b437"

class ScanState:
    def __init__(self): self._lock = threading.Lock(); self._states = {}
    def create(self, sid):
        with self._lock: self._states[sid] = {'progress': 0, 'status': 'Initializing...', 'logs': [], 'checks': {}, 'final': None}
    def get(self, sid):
        with self._lock: return self._states.get(sid)
    def update(self, sid, prog, stat, check=None, data=None):
        with self._lock:
            s = self._states.get(sid)
            if s:
                s['progress'] = min(prog, 100); s['status'] = stat
                if check: s['checks'][check] = data
    def log(self, sid, msg, lvl="INFO"):
        with self._lock:
            s = self._states.get(sid)
            if s:
                s['logs'].append({'t': datetime.datetime.now().strftime("%H:%M:%S"), 'm': msg, 'l': lvl})
                if len(s['logs']) > 100: s['logs'] = s['logs'][-100:]
    def done(self, sid, res):
        with self._lock:
            s = self._states.get(sid)
            if s: s['final'] = res

state = ScanState()

def safe_call(func, default=None, sid=None):
    try: return func()
    except requests.exceptions.Timeout:
        if sid: state.log(sid, "⚠️ Timeout", "WARNING")
        return default if default is not None else {"error": "timeout"}
    except requests.exceptions.ConnectionError:
        if sid: state.log(sid, "⚠️ Connection Error", "WARNING")
        return default if default is not None else {"error": "conn"}
    except requests.exceptions.HTTPError as e:
        if sid: state.log(sid, f"⚠️ HTTP {e.response.status_code}", "WARNING")
        return default if default is not None else {"error": f"http_{e.response.status_code}"}
    except Exception as e:
        if sid: state.log(sid, f"⚠️ Error: {str(e)[:60]}", "ERROR")
        return default if default is not None else {"error": str(e)[:60]}

def extract_domain(url):
    if not url: raise ValueError("Empty URL")
    clean = url.strip()
    if not clean.startswith(('http://', 'https://')): clean = 'https://' + clean
    parsed = urlparse(clean)
    dom = parsed.netloc.lower()
    if ':' in dom: dom = dom.split(':')[0]
    if '@' in dom: dom = dom.split('@')[1]
    
    analysis_sites = ['virustotal.com', 'urlscan.io']
    if any(s in dom for s in analysis_sites):
        search = parsed.path + ' ' + parsed.query
        matches = re.findall(r'(?:domain|url|q)=([a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,})', search)
        if matches:
            for m in matches:
                if not any(s in m for s in analysis_sites): return m.lower(), clean
        matches = re.findall(r'/([a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,})', search)
        if matches:
            for m in matches:
                if not any(s in m for s in analysis_sites): return m.lower(), clean
                
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', dom): return dom, clean
    
    parts = dom.split('.')
    
    cc_tlds = {
        '.com.br', '.net.br', '.org.br', '.gov.br', '.edu.br', '.mil.br', '.art.br', '.inf.br',
        '.co.uk', '.org.uk', '.me.uk', '.ac.uk', '.gov.uk', '.ltd.uk', '.plc.uk',
        '.com.au', '.net.au', '.org.au', '.edu.au', '.gov.au',
        '.co.nz', '.net.nz', '.org.nz', '.geek.nz', '.gen.nz',
        '.co.jp', '.or.jp', '.ne.jp', '.ac.jp', '.go.jp',
        '.co.in', '.net.in', '.org.in', '.gen.in', '.firm.in',
        '.co.za', '.org.za', '.net.za', '.gov.za',
        '.com.mx', '.net.mx', '.org.mx', '.gob.mx',
        '.com.cn', '.net.cn', '.org.cn', '.edu.cn', '.gov.cn',
        '.com.tw', '.net.tw', '.org.tw', '.edu.tw',
        '.com.ru', '.net.ru', '.org.ru',
        '.co.kr', '.net.kr', '.org.kr', '.go.kr',
        '.com.sg', '.net.sg', '.org.sg',
        '.com.my', '.net.my', '.org.my',
        '.com.ph', '.net.ph', '.org.ph',
        '.com.hk', '.net.hk', '.org.hk',
        '.com.id', '.net.id', '.org.id', '.ac.id',
        '.com.ar', '.net.ar', '.org.ar',
        '.com.ve', '.net.ve', '.org.ve',
        '.com.cl', '.net.cl', '.org.cl',
        '.com.co', '.net.co', '.org.co',
        '.com.pe', '.net.pe', '.org.pe',
        '.com.ec', '.net.ec', '.org.ec',
        '.com.py', '.net.py', '.org.py',
        '.com.uy', '.net.uy', '.org.uy',
        '.pp.ua', '.com.ua', '.net.ua', '.org.ua',
        '.co.th', '.or.th', '.go.th', '.ac.th',
        '.com.vn', '.net.vn', '.org.vn',
        '.co.il', '.org.il', '.net.il',
        '.com.tr', '.net.tr', '.org.tr',
        '.co.at', '.or.at', '.ac.at',
        '.co.se', '.org.se',
    }
    
    if len(parts) >= 3:
        potential_tld = '.'.join(parts[-2:])
        if '.' + potential_tld in cc_tlds:
            return '.'.join(parts[-3:]), clean
            
    if len(parts) >= 2:
        return '.'.join(parts[-2:]), clean
    return dom, clean

def check_google(url, domain, sid):
    state.log(sid, "🌐 Checking Google Safe Browsing...", "INFO")
    state.update(sid, 10, "Google Safe Browsing...", "google", {"s": "loading"})
    def do_check(u):
        p = {"client": {"clientId": "pro-v4", "clientVersion": "4.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION", "TRICK_TO_BILL"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": u}]}}
        r = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", params={"key": GOOGLE_KEY}, json=p, timeout=15)
        r.raise_for_status(); return r.json()
    threats = []
    for u in [url, f"https://{domain}", f"http://{domain}"]:
        res = safe_call(lambda u=u: do_check(u), {}, sid)
        if "matches" in res:
            for m in res["matches"]:
                t = m.get("threatType", "Unknown")
                if t not in threats: threats.append(t)
    if threats:
        state.log(sid, f"⚠️ Google Found: {', '.join(threats)}", "WARNING")
        state.update(sid, 20, "Google: Threats!", "google", {"s": "bad", "d": {"safe": False, "msg": f"⚠️ {', '.join(threats)}", "threats": threats}})
    else:
        state.log(sid, "✅ Google: Clean", "SUCCESS")
        state.update(sid, 20, "Google: Clean", "google", {"s": "ok", "d": {"safe": True, "msg": "✅ Clean"}})

def check_vt(domain, url, sid):
    state.log(sid, "🦠 Checking VirusTotal (Domain)...", "INFO")
    state.update(sid, 25, "VirusTotal Domain...", "vt", {"s": "loading"})
    def do_dom():
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": VT_KEY}, timeout=15)
        if r.status_code == 404: return {"nf": True}
        r.raise_for_status(); return r.json()
    res = safe_call(do_dom, {"nf": False}, sid)
    vendors_flagged = []
    if "error" not in res and not res.get("nf"):
        attrs = res.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        last_res = attrs.get("last_analysis_results", {})
        for vname, vdata in last_res.items():
            if isinstance(vdata, dict):
                cat = str(vdata.get("category", "")).lower()
                rtxt = str(vdata.get("result", "")).lower()
                if cat == "malicious": vendors_flagged.append(f"{vname}: {vdata.get('result', 'Malicious')}")
                elif any(k in rtxt for k in ['phishing', 'phish', 'credential']): vendors_flagged.append(f"{vname}: {vdata.get('result', '')}")
        if vendors_flagged:
            state.log(sid, f"⚠️ VT Domain: {len(vendors_flagged)} vendors flagged!", "WARNING")
            state.update(sid, 45, "VT Domain: Threats!", "vt", {"s": "bad", "d": {"safe": False, "mal": len(vendors_flagged), "vendors": vendors_flagged[:10], "stats": stats}})
        else:
            state.log(sid, f"✅ VT Domain: Clean ({sum(stats.values())} engines)", "SUCCESS")
            state.update(sid, 45, "VT Domain: Clean", "vt", {"s": "ok", "d": {"safe": True, "msg": f"✅ Clean ({sum(stats.values())} engines)", "stats": stats}})
    else:
        state.update(sid, 45, "VT Domain: N/A", "vt", {"s": "warn", "d": {"safe": True, "msg": "ℹ️ Not in database"}})
        
    state.log(sid, "🔗 Checking VirusTotal (URL)...", "INFO")
    state.update(sid, 50, "VT URL...", "vt_url", {"s": "loading"})
    def do_url():
        b64 = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{b64}", headers={"x-apikey": VT_KEY}, timeout=15)
        if r.status_code == 404: return {"nf": True}
        r.raise_for_status(); return r.json()
    res2 = safe_call(do_url, {"nf": False}, sid)
    if "error" not in res2 and not res2.get("nf"):
        attrs2 = res2.get("data", {}).get("attributes", {})
        stats2 = attrs2.get("last_analysis_stats", {})
        mal2 = stats2.get("malicious", 0)
        if mal2 > 0:
            state.log(sid, f"⚠️ VT URL: {mal2} malicious!", "WARNING")
            state.update(sid, 60, "VT URL: Threats!", "vt_url", {"s": "bad", "d": {"safe": False, "mal": mal2, "msg": f"⚠️ {mal2} detections", "stats": stats2}})
        else:
            state.log(sid, "✅ VT URL: Clean", "SUCCESS")
            state.update(sid, 60, "VT URL: Clean", "vt_url", {"s": "ok", "d": {"safe": True, "msg": "✅ Clean", "stats": stats2}})
    else:
        state.update(sid, 60, "VT URL: N/A", "vt_url", {"s": "ok", "d": {"safe": True, "msg": "ℹ️ Not scanned"}})

def check_urlscan_api(url, domain, sid):
    state.log(sid, "📊 Checking URLScan.io...", "INFO")
    state.update(sid, 65, "URLScan.io...", "urlscan", {"s": "loading"})
    headers = {"API-Key": URLSCAN_KEY} if URLSCAN_KEY else {}
    max_score, is_mal = 0, False
    
    # FIX: Try URL search first, but if it 400s, fall back to domain only
    def do_search_url():
        q = f"url:{requests.utils.quote(url, safe='')}"
        r = requests.get(f"https://urlscan.io/api/v1/search/?q={q}", headers=headers, timeout=15)
        r.raise_for_status(); return r.json()
    
    url_res = safe_call(do_search_url, None, sid)
    
    if url_res and "error" not in url_res:
        for r in url_res.get("results", []):
            sc = r.get("score", 0); max_score = max(max_score, sc)
            verd = r.get("verdicts", {}).get("overall", {})
            if verd.get("malicious") == True: is_mal = True
            tags = r.get("tags", [])
            if any(t in tags for t in ['phishing', 'malware']): is_mal = True
    else:
        # FIX: URL search failed (likely 400 due to long URL), fall back to domain
        state.log(sid, "ℹ️ URLScan: URL search failed, trying domain...", "INFO")
        def do_search_dom():
            r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", headers=headers, timeout=15)
            r.raise_for_status(); return r.json()
        dom_res = safe_call(do_search_dom, {"results": []}, sid)
        for r in dom_res.get("results", []):
            sc = r.get("score", 0); max_score = max(max_score, sc)
            verd = r.get("verdicts", {}).get("overall", {})
            if verd.get("malicious") == True: is_mal = True
            tags = r.get("tags", [])
            if any(t in tags for t in ['phishing', 'malware']): is_mal = True
            
    if is_mal:
        state.log(sid, f"⚠️ URLScan: MALICIOUS ({max_score}/100)", "WARNING")
        state.update(sid, 75, "URLScan: Malicious!", "urlscan", {"s": "bad", "d": {"safe": False, "msg": f"⚠️ Malicious (Score: {max_score})", "score": max_score}})
    elif max_score > 30:
        state.log(sid, f"⚠️ URLScan: Suspicious ({max_score}/100)", "WARNING")
        state.update(sid, 75, "URLScan: Suspicious", "urlscan", {"s": "warn", "d": {"safe": False, "msg": f"⚠️ Suspicious ({max_score})", "score": max_score}})
    else:
        state.log(sid, f"✅ URLScan: Clean ({max_score}/100)", "SUCCESS")
        state.update(sid, 75, "URLScan: Clean", "urlscan", {"s": "ok", "d": {"safe": True, "msg": f"✅ Score {max_score}/100", "score": max_score}})

def check_ssl_api(url, sid):
    state.log(sid, "🔐 Checking SSL...", "INFO")
    state.update(sid, 5, "SSL Check...", "ssl", {"s": "loading"})
    try:
        dom = urlparse(url).netloc
        if ':' in dom: dom = dom.split(':')[0]
        ctx = ssl.create_default_context()
        with socket.create_connection((dom, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=dom) as ssock:
                cert = ssock.getpeercert()
                na = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days = (na - datetime.datetime.now()).days
                iss = ', '.join(f"{k}={v}" for i in cert.get('issuer',()) for k,v in i)[:100]
                san = [n[1].lower() for n in cert.get('subjectAltName',[]) if n[0]=='DNS']
                match = dom.lower() in san or any(dom.lower().endswith('.'+s) for s in san)
                self_signed = iss == str(cert.get('subject',''))
                status = "✅ Valid" if (days>30 and match and not self_signed) else "❌ Invalid/Mismatch/Self-Signed"
                state.log(sid, f"📊 SSL: {days} days left", "INFO")
                state.update(sid, 10, "SSL: Done", "ssl", {"s": "ok" if days>30 and match else "bad", "d": {"days": days, "iss": iss, "match": match, "self": self_signed, "status": status}})
    except socket.gaierror:
        # FIX: Hide raw socket error, show user-friendly message
        state.log(sid, "⚠️ SSL: Domain cannot be resolved", "WARNING")
        state.update(sid, 10, "SSL: Unreachable", "ssl", {"s": "warn", "d": {"status": "❌ Domain does not resolve (offline/dead)"}})
    except ConnectionRefusedError:
        state.log(sid, "⚠️ SSL: Connection refused", "WARNING")
        state.update(sid, 10, "SSL: Refused", "ssl", {"s": "warn", "d": {"status": "❌ Connection refused (port closed)"}})
    except socket.timeout:
        state.log(sid, "⚠️ SSL: Connection timeout", "WARNING")
        state.update(sid, 10, "SSL: Timeout", "ssl", {"s": "warn", "d": {"status": "❌ Connection timed out"}})
    except Exception as e:
        err = str(e)
        # FIX: Map common errors to friendly messages
        if "11001" in err or "getaddrinfo" in err:
            state.log(sid, "⚠️ SSL: Domain does not resolve", "WARNING")
            state.update(sid, 10, "SSL: Unreachable", "ssl", {"s": "warn", "d": {"status": "❌ Domain does not resolve (offline/dead)"}})
        elif "certificate verify" in err.lower():
            state.log(sid, "⚠️ SSL: Invalid certificate", "WARNING")
            state.update(sid, 10, "SSL: Invalid Cert", "ssl", {"s": "bad", "d": {"status": "❌ Invalid SSL certificate"}})
        else:
            state.log(sid, f"⚠️ SSL: {err[:50]}", "WARNING")
            state.update(sid, 10, "SSL: Error", "ssl", {"s": "warn", "d": {"status": f"❌ SSL unavailable"}})

def check_whois_api(domain, sid):
    state.log(sid, "📅 Checking WHOIS...", "INFO")
    state.update(sid, 12, "WHOIS...", "whois", {"s": "loading"})
    def do():
        try:
            w = whois.whois(domain, timeout=10)
            if isinstance(w, dict) and w.get('text'): return w['text']
            return w
        except: return raw_whois(domain)
    res = safe_call(do, None, sid)
    if res and isinstance(res, str):
        p = parse_whois(res)
        if p:
            state.log(sid, f"📊 Age: {p.get('days', 'N/A')} days", "INFO")
            state.update(sid, 15, "WHOIS: Done", "whois", {"s": "ok" if p.get('days',999)>30 else "bad", "d": p}); return
    elif res and hasattr(res, 'creation_date') and res.creation_date:
        cd = res.creation_date[0] if isinstance(res.creation_date, list) else res.creation_date
        if isinstance(cd, datetime.datetime):
            days = (datetime.datetime.now() - cd).days
            p = {'days': days, 'years': round(days/365,1), 'created': cd.strftime('%Y-%m-%d'), 'status': '✅ Established' if days>365 else '❌ Very New'}
            state.log(sid, f"📊 Age: {days} days", "INFO")
            state.update(sid, 15, "WHOIS: Done", "whois", {"s": "ok" if days>30 else "bad", "d": p}); return
    state.update(sid, 15, "WHOIS: Unavailable", "whois", {"s": "warn", "d": {"status": "⚠️ WHOIS unavailable"}})

def raw_whois(dom):
    try:
        tld = dom.split('.')[-1]
        srvs = {'br':'whois.registro.br','cn':'whois.cnnic.cn','ru':'whois.tcinet.ru','tk':'whois.freenom.com','ml':'whois.freenom.com'}
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(10)
        s.connect((srvs.get(tld, 'whois.iana.org'), 43)); s.send((dom+"\r\n").encode())
        d=b""
        while True:
            tmp=s.recv(4096)
            if not tmp: break
            d+=tmp
        s.close(); return d.decode('utf-8', errors='ignore')
    except: return None

def parse_whois(txt):
    m = re.search(r'(?:created|creation\s*date|registered)[:\s]+(.+?)(?:\n|$)', txt, re.I)
    if m:
        ds = m.group(1).strip().split()[0]
        for fmt in ['%Y-%m-%d','%Y/%m/%d','%d.%m.%Y','%Y%m%d']:
            try:
                dt = datetime.datetime.strptime(ds, fmt); days = (datetime.datetime.now()-dt).days
                return {'days': days, 'years': round(days/365,1), 'created': dt.strftime('%Y-%m-%d'), 'status': '✅ Established' if days>365 else '❌ Very New'}
            except: pass
    return None

def check_dns_api(domain, sid):
    state.log(sid, "📧 Checking DNS...", "INFO")
    state.update(sid, 80, "DNS...", "dns", {"s": "loading"})
    res = {}
    is_dead = False
    try:
        a = dns.resolver.resolve(domain, 'A', lifetime=5); res['ip'] = [str(r) for r in a]
    except dns.resolver.NXDOMAIN:
        # FIX: NXDOMAIN = DEAD DOMAIN = MAJOR THREAT INDICATOR
        res['ip'] = "❌ NXDOMAIN (Dead Domain)"
        is_dead = True
        state.log(sid, "❌ DNS: NXDOMAIN - Domain is DEAD!", "ERROR")
    except dns.resolver.NoAnswer:
        res['ip'] = "⚠️ No A records"
    except: res['ip'] = "⚠️ Error"
    try:
        spf = dns.resolver.resolve(domain, 'TXT', lifetime=5); res['spf'] = "✅ Found" if any('v=spf1' in str(x) for x in spf) else "❌ No"
    except: res['spf'] = "❌ No"
    try:
        dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT', lifetime=5); res['dmarc'] = "✅ Found" if any('v=DMARC1' in str(x) for x in dmarc) else "❌ No"
    except: res['dmarc'] = "❌ No"
    try:
        mx = dns.resolver.resolve(domain, 'MX', lifetime=5); res['mx'] = f"✅ {len(mx)} records"
    except: res['mx'] = "❌ No"
    
    # FIX: If NXDOMAIN, mark as BAD (critical threat for phishing)
    if is_dead:
        state.update(sid, 90, "DNS: DEAD DOMAIN!", "dns", {"s": "bad", "d": res})
    else:
        state.log(sid, "📊 DNS: Done", "INFO")
        state.update(sid, 90, "DNS: Done", "dns", {"s": "ok", "d": res})

def check_patterns(domain, url, sid):
    state.log(sid, "🔍 Analyzing Patterns...", "INFO")
    state.update(sid, 95, "Patterns...", "patterns", {"s": "loading"})
    finds = []
    dl, pl = domain.lower(), urlparse(url).path.lower()
    if any(k in pl for k in ['autentica','login','signin','password','senha','conta','account','verify','validate']): finds.append("⚠️ Authentication path keyword detected")
    if any(k in pl+dl for k in ['visa','mastercard','debit','credit','cartao','bank','pix','boleto','promocion','premio']): finds.append("⚠️ Financial/Promotional keyword detected")
    if re.search(r'[0-9a-f]{32,}', dl): finds.append("⚠️ Hex/Hash pattern in domain")
    if len(url) > 150: finds.append("⚠️ Abnormally long URL (Obfuscation likely)")
    if dl.count('.') > 3: finds.append("⚠️ Excessive subdomains")
    if any(dl.endswith(t) for t in ['.tk','.ml','.ga','.cf','.xyz','.top']): finds.append("⚠️ Highly suspicious TLD")
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', dl): finds.append("⚠️ Raw IP address used instead of domain")
    state.log(sid, f"📊 Patterns: {len(finds)} findings", "INFO")
    state.update(sid, 100, "Complete!", "patterns", {"s": "ok" if not finds else "bad", "d": {"findings": finds}})

def run_scan(url, sid):
    try:
        domain, clean = extract_domain(url)
        state.log(sid, f"🔍 Extracted Domain: {domain}", "INFO")
        check_ssl_api(clean, sid)
        check_whois_api(domain, sid)
        check_google(clean, domain, sid)
        check_vt(domain, clean, sid)
        check_urlscan_api(clean, domain, sid)
        check_dns_api(domain, sid)
        check_patterns(domain, url, sid)
        
        checks = state.get(sid)['checks']
        score = 100
        
        # FIX: Smarter scoring with cross-referencing
        vt_url_bad = checks.get('vt_url', {}).get('s') == 'bad'
        dns_dead = checks.get('dns', {}).get('s') == 'bad'
        dns_data = checks.get('dns', {}).get('d', {})
        is_nxdomain = isinstance(dns_data.get('ip'), str) and 'NXDOMAIN' in dns_data.get('ip', '')
        
        for k, v in checks.items():
            s = v.get('s')
            if s == 'bad':
                if k in ['vt', 'vt_url']: score -= 25
                elif k == 'google': score -= 30
                elif k == 'urlscan': score -= 20
                elif k == 'ssl': score -= 5  # Reduced: SSL fail on dead domain is expected
                elif k == 'whois': score -= 5  # Reduced: WHOIS fail on dead domain is expected
                elif k == 'dns': score -= 15
                elif k == 'patterns': score -= len(v.get('d', {}).get('findings', [])) * 5
        
        # FIX: Dead domain + any VT detection = CRITICAL
        if is_nxdomain:
            score -= 15  # Dead domain penalty
            state.log(sid, "❌ SCORE PENALTY: Dead domain detected (-15)", "WARNING")
            if vt_url_bad:
                score -= 15  # Extra penalty for dead + malicious
                state.log(sid, "❌ SCORE PENALTY: Dead domain + VT malicious (-15 extra)", "ERROR")
        
        score = max(0, min(100, score))
        final_res = {'url': url, 'domain': domain, 'score': score, 'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'checks': {k: v.get('d') for k, v in checks.items()}}
        state.done(sid, final_res)
    except Exception as e:
        state.log(sid, f"❌ FATAL: {str(e)}", "ERROR")
        state.update(sid, 100, "Error", None, None)
        state.done(sid, {"error": str(e)})

@app.route('/')
def index(): return HTML_UI

@app.route('/api/start', methods=['POST'])
def start():
    url = request.json.get('url')
    if not url: return jsonify({"error": "No URL"}), 400
    if not url.startswith(('http://', 'https://')): url = 'https://' + url
    sid = f"scan_{int(time.time()*1000)}"; state.create(sid)
    threading.Thread(target=run_scan, args=(url, sid)).start()
    return jsonify({"scan_id": sid})

@app.route('/api/progress/<sid>')
def progress(sid):
    d = state.get(sid)
    if not d: return jsonify({"error": "Not found"}), 404
    return jsonify({"progress": d['progress'], "status": d['status'], "logs": d['logs'], "checks": d['checks'], "final": d['final']})

@app.route('/download/<ftype>/<sid>')
def download(ftype, sid):
    d = state.get(sid)
    if not d or not d.get('final'): return "No results", 404
    res = d['final']
    if ftype == 'html':
        html = f"""<html><head><title>Security Report</title><style>body{{font-family:Arial;padding:40px;background:#f8f9fa;}}.box{{background:#fff;padding:20px;margin-bottom:20px;border-radius:8px;box-shadow:0 4px 6px rgba(0,0,0,0.1);}}.red{{color:#dc3545;}}.green{{color:#28a745;}}h1{{color:#1e3c72;}}</style></head><body><div class="box"><h1>🛡️ Security Analysis Report</h1><p><strong>URL:</strong> {res.get('url','')}</p><p><strong>Domain:</strong> {res.get('domain','')}</p><p><strong>Score:</strong> <span class="{'red' if res.get('score',0) < 50 else 'green'}">{res.get('score',0)}/100</span></p><p><strong>Time:</strong> {res.get('time','')}</p></div><div class="box"><h3>API Details</h3><pre>{json.dumps(res.get('checks',{}), indent=4)}</pre></div></body></html>"""
        buf = BytesIO(html.encode()); return send_file(buf, as_attachment=True, download_name='report.html', mimetype='text/html')
    else:
        txt = f"Security Report\n================\nURL: {res.get('url','')}\nDomain: {res.get('domain','')}\nScore: {res.get('score',0)}/100\nTime: {res.get('time','')}\n\nAPI Details:\n{json.dumps(res.get('checks',{}), indent=2)}"
        buf = BytesIO(txt.encode()); return send_file(buf, as_attachment=True, download_name='report.txt', mimetype='text/plain')

HTML_UI = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ultimate Pro Phishing Analyzer</title>
    <style>
        :root { --bg: #0f172a; --card: #1e293b; --border: #334155; --text: #f1f5f9; --muted: #94a3b8; --accent: #3b82f6; --danger: #ef4444; --success: #22c55e; --warn: #f59e0b; }
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
        body { background: var(--bg); color: var(--text); min-height: 100vh; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { text-align: center; padding: 40px 20px; border-bottom: 1px solid var(--border); margin-bottom: 30px; background: linear-gradient(180deg, #1e293b 0%, var(--bg) 100%); }
        header h1 { font-size: 2.5rem; background: linear-gradient(90deg, var(--accent), #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 10px; letter-spacing: -0.5px; }
        header p { color: var(--muted); font-size: 1.1rem; }
        .input-box { display: flex; gap: 10px; max-width: 950px; margin: 0 auto 20px; background: var(--card); padding: 8px; border-radius: 14px; border: 1px solid var(--border); box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
        .input-box input { flex: 1; background: transparent; border: none; color: var(--text); font-size: 1.1rem; padding: 14px; outline: none; }
        .input-box button { background: var(--accent); color: white; border: none; padding: 14px 32px; border-radius: 10px; font-weight: bold; cursor: pointer; transition: 0.2s; font-size: 1rem; }
        .input-box button:hover { background: #2563eb; transform: translateY(-1px); }
        .input-box button:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        .clear-btn { background: transparent !important; color: var(--muted) !important; padding: 14px 20px !important; }
        .clear-btn:hover { color: var(--danger) !important; background: rgba(239, 68, 68, 0.1) !important; }
        .actions { display: flex; gap: 12px; justify-content: center; margin-bottom: 25px; flex-wrap: wrap; }
        .btn-sm { background: var(--card); color: var(--muted); border: 1px solid var(--border); padding: 10px 20px; border-radius: 8px; cursor: pointer; font-size: 0.9rem; transition: 0.2s; display: none; text-decoration: none; }
        .btn-sm:hover { background: var(--border); color: white; }
        .progress-wrapper { max-width: 950px; margin: 0 auto 30px; display: none; }
        .progress-header { display: flex; justify-content: space-between; margin-bottom: 10px; font-size: 0.95rem; color: var(--muted); font-weight: 500; }
        .progress-bar { width: 100%; height: 10px; background: var(--card); border-radius: 5px; overflow: hidden; border: 1px solid var(--border); }
        .progress-fill { height: 100%; width: 0%; background: linear-gradient(90deg, var(--accent), #a855f7); transition: width 0.4s ease; border-radius: 5px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 24px; opacity: 0.4; transition: all 0.3s ease; }
        .card.active { opacity: 1; transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0,0,0,0.2); }
        .card.ok { border-color: var(--success); box-shadow: 0 0 15px rgba(34, 197, 94, 0.1); }
        .card.bad { border-color: var(--danger); box-shadow: 0 0 15px rgba(239, 68, 68, 0.15); animation: pulse 2s infinite; }
        .card.warn { border-color: var(--warn); box-shadow: 0 0 15px rgba(245, 158, 11, 0.1); }
        @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.2); } 70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); } 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); } }
        .card-title { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; font-weight: 600; font-size: 1.05rem; }
        .status-badge { font-size: 0.75rem; padding: 5px 10px; border-radius: 6px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .s-loading { background: #334155; color: #64748b; }
        .s-ok { background: #166534; color: #bbf7d0; }
        .s-bad { background: #991b1b; color: #fecaca; }
        .s-warn { background: #854d0e; color: #fef08a; }
        .card-body { font-size: 0.9rem; color: var(--muted); line-height: 1.7; }
        .detail-row { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(51, 65, 85, 0.5); padding: 8px 0; }
        .detail-row:last-child { border: none; }
        .detail-val { font-weight: 500; color: var(--text); text-align: right; max-width: 60%; word-break: break-all; }
        .vendor-list { max-height: 180px; overflow-y: auto; margin-top: 12px; background: rgba(0,0,0,0.2); padding: 10px; border-radius: 8px; }
        .vendor-item { color: var(--danger); padding: 4px 0; border-bottom: 1px solid rgba(51, 65, 85, 0.3); display: flex; gap: 8px; }
        .vendor-item:last-child { border: none; }
        .log-container { background: #020617; border: 1px solid var(--border); border-radius: 14px; padding: 16px; height: 280px; overflow-y: auto; font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace; font-size: 0.85rem; display: none; box-shadow: inset 0 0 30px rgba(0,0,0,0.5); }
        .log-line { padding: 3px 0; display: flex; gap: 15px; border-bottom: 1px solid rgba(51, 65, 85, 0.2); }
        .log-time { color: var(--accent); min-width: 70px; }
        .log-INFO { color: #cbd5e1; }
        .log-SUCCESS { color: var(--success); font-weight: 600; }
        .log-WARNING { color: var(--warn); }
        .log-ERROR { color: var(--danger); font-weight: 600; }
        .score-display { text-align: center; padding: 30px; display: none; margin-bottom: 20px; }
        .score-circle { width: 140px; height: 140px; border-radius: 50%; border: 8px solid var(--border); display: flex; align-items: center; justify-content: center; font-size: 2.5rem; font-weight: bold; margin: 0 auto 20px; transition: all 0.5s; }
        .score-text { font-size: 1.5rem; font-weight: 600; letter-spacing: 1px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Ultimate Pro Phishing Analyzer</h1>
            <p>Real-time multi-engine threat analysis & detection</p>
        </header>
        
        <div class="input-box">
            <input type="text" id="urlInput" placeholder="Paste any suspicious URL here to analyze...">
            <button id="scanBtn" onclick="startScan()">🔍 Analyze</button>
            <button class="clear-btn" onclick="clearAll()">✖</button>
        </div>
        
        <div class="actions">
            <button class="btn-sm" id="copyBtn" onclick="copyLink()">📋 Copy Link</button>
            <button class="btn-sm" id="dlHtml" onclick="download('html')">📥 Download HTML</button>
            <button class="btn-sm" id="dlTxt" onclick="download('txt')">📥 Download TXT</button>
        </div>
        
        <div class="progress-wrapper" id="progressWrapper">
            <div class="progress-header">
                <span id="pStatus">Initializing...</span>
                <span id="pPercent">0%</span>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" id="pFill"></div>
            </div>
        </div>
        
        <div class="score-display" id="scoreDisplay">
            <div class="score-circle" id="scoreCircle">0</div>
            <div class="score-text" id="scoreText">ANALYZING...</div>
        </div>

        <div class="grid">
            <div class="card" id="c-google">
                <div class="card-title">🌐 Google Safe Browsing <span class="status-badge s-loading" id="st-google">Waiting</span></div>
                <div class="card-body" id="d-google"></div>
            </div>
            <div class="card" id="c-vt">
                <div class="card-title">🦠 VirusTotal (Domain) <span class="status-badge s-loading" id="st-vt">Waiting</span></div>
                <div class="card-body" id="d-vt"></div>
            </div>
            <div class="card" id="c-vt_url">
                <div class="card-title">🔗 VirusTotal (URL) <span class="status-badge s-loading" id="st-vt_url">Waiting</span></div>
                <div class="card-body" id="d-vt_url"></div>
            </div>
            <div class="card" id="c-urlscan">
                <div class="card-title">📊 URLScan.io <span class="status-badge s-loading" id="st-urlscan">Waiting</span></div>
                <div class="card-body" id="d-urlscan"></div>
            </div>
            <div class="card" id="c-ssl">
                <div class="card-title">🔐 SSL Certificate <span class="status-badge s-loading" id="st-ssl">Waiting</span></div>
                <div class="card-body" id="d-ssl"></div>
            </div>
            <div class="card" id="c-whois">
                <div class="card-title">📅 WHOIS / Age <span class="status-badge s-loading" id="st-whois">Waiting</span></div>
                <div class="card-body" id="d-whois"></div>
            </div>
            <div class="card" id="c-dns">
                <div class="card-title">📧 DNS Security <span class="status-badge s-loading" id="st-dns">Waiting</span></div>
                <div class="card-body" id="d-dns"></div>
            </div>
            <div class="card" id="c-patterns">
                <div class="card-title">🔍 URL Patterns <span class="status-badge s-loading" id="st-patterns">Waiting</span></div>
                <div class="card-body" id="d-patterns"></div>
            </div>
        </div>

        <div class="log-container" id="logBox"></div>
    </div>

    <script>
        let currentSid = null;
        let currentUrl = '';

        async function startScan() {
            const url = document.getElementById('urlInput').value.trim();
            if (!url) return alert('Please enter a URL to analyze.');
            currentUrl = url;
            const btn = document.getElementById('scanBtn');
            btn.disabled = true; btn.innerText = '⏳ Scanning...';
            clearUI();
            document.getElementById('progressWrapper').style.display = 'block';
            document.getElementById('logBox').style.display = 'block';
            
            try {
                const res = await fetch('/api/start', {
                    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url})
                });
                const data = await res.json();
                if(data.error) throw new Error(data.error);
                currentSid = data.scan_id;
                pollProgress();
            } catch(e) {
                alert('Error starting scan: ' + e.message);
                btn.disabled = false; btn.innerText = '🔍 Analyze';
            }
        }

        function pollProgress() {
            if (!currentSid) return;
            fetch(`/api/progress/${currentSid}`).then(r => r.json()).then(data => {
                document.getElementById('pFill').style.width = data.progress + '%';
                document.getElementById('pPercent').innerText = data.progress + '%';
                document.getElementById('pStatus').innerText = data.status;
                
                const logBox = document.getElementById('logBox');
                logBox.innerHTML = data.logs.map(l => `<div class="log-line"><span class="log-time">[${l.t}]</span> <span class="log-${l.l}">${l.m}</span></div>`).join('');
                logBox.scrollTop = logBox.scrollHeight;
                
                for (let key in data.checks) {
                    const check = data.checks[key];
                    const card = document.getElementById('c-' + key);
                    const badge = document.getElementById('st-' + key);
                    const body = document.getElementById('d-' + key);
                    if (!card) continue;
                    card.className = 'card active ' + check.s;
                    if (check.s === 'loading') {
                        badge.className = 'status-badge s-loading'; badge.innerText = 'Scanning...';
                        body.innerHTML = '<div style="color:var(--muted);font-style:italic;">Waiting for response...</div>';
                    } else {
                        badge.className = 'status-badge s-' + check.s;
                        badge.innerText = check.s === 'ok' ? 'Clean' : check.s === 'bad' ? 'Threat' : 'Warning';
                        body.innerHTML = renderData(key, check.d);
                    }
                }
                
                if (data.progress >= 100 && data.final) {
                    const score = data.final.score;
                    const circle = document.getElementById('scoreCircle');
                    const text = document.getElementById('scoreText');
                    document.getElementById('scoreDisplay').style.display = 'block';
                    circle.innerText = score;
                    if (score >= 80) {
                        circle.style.borderColor = 'var(--success)'; circle.style.color = 'var(--success)';
                        text.innerText = 'LOW RISK'; text.style.color = 'var(--success)';
                    } else if (score >= 50) {
                        circle.style.borderColor = 'var(--warn)'; circle.style.color = 'var(--warn)';
                        text.innerText = 'MEDIUM RISK'; text.style.color = 'var(--warn)';
                    } else {
                        circle.style.borderColor = 'var(--danger)'; circle.style.color = 'var(--danger)';
                        text.innerText = 'HIGH RISK'; text.style.color = 'var(--danger)';
                    }
                    document.getElementById('scanBtn').disabled = false; document.getElementById('scanBtn').innerText = '🔍 Analyze';
                    document.querySelectorAll('.btn-sm').forEach(b => b.style.display = 'inline-block');
                    return;
                }
                setTimeout(pollProgress, 400);
            }).catch(e => { console.error(e); setTimeout(pollProgress, 1000); });
        }

        function renderData(key, d) {
            if (!d) return '';
            let h = '';
            if (key === 'google') {
                h += `<div class="detail-row"><span>Status</span><span class="detail-val">${d.msg}</span></div>`;
                if(d.threats) d.threats.forEach(t => h += `<div style="color:var(--danger);margin-top:8px;font-weight:600;">⚠️ ${t}</div>`);
            } else if (key === 'vt' || key === 'vt_url') {
                h += `<div class="detail-row"><span>Result</span><span class="detail-val">${d.msg || (d.safe ? '✅ Clean' : '⚠️ Threat')}</span></div>`;
                if(d.stats) h += `<div class="detail-row"><span>Malicious</span><span class="detail-val" style="color:${d.stats.malicious > 0 ? 'var(--danger)' : 'var(--text)'}">${d.stats.malicious || 0}</span></div><div class="detail-row"><span>Suspicious</span><span class="detail-val">${d.stats.suspicious || 0}</span></div>`;
                if(d.vendors && d.vendors.length > 0) {
                    h += `<div style="margin-top:12px;font-weight:700;color:var(--danger);margin-bottom:6px;">Flagged by:</div><div class="vendor-list">`;
                    d.vendors.forEach(v => h += `<div class="vendor-item">🔴 ${v}</div>`);
                    h += `</div>`;
                }
            } else if (key === 'urlscan') {
                h += `<div class="detail-row"><span>Score</span><span class="detail-val" style="color:${(d.score||0) > 30 ? 'var(--danger)' : 'var(--text)'}">${d.score || 'N/A'}/100</span></div>`;
                h += `<div class="detail-row"><span>Verdict</span><span class="detail-val">${d.msg}</span></div>`;
            } else if (key === 'ssl') {
                h += `<div class="detail-row"><span>Status</span><span class="detail-val">${d.status}</span></div>`;
                if(d.days != null) h += `<div class="detail-row"><span>Days Left</span><span class="detail-val">${d.days}</span></div>`;
                if(d.match != null) h += `<div class="detail-row"><span>Domain Match</span><span class="detail-val">${d.match ? '✅ Yes' : '❌ No'}</span></div>`;
                if(d.self) h += `<div class="detail-row"><span>Self-Signed</span><span class="detail-val" style="color:var(--danger)">❌ Yes</span></div>`;
                if(d.iss) h += `<div class="detail-row"><span>Issuer</span><span class="detail-val" style="font-size:0.8rem;opacity:0.8">${d.iss}</span></div>`;
            } else if (key === 'whois') {
                h += `<div class="detail-row"><span>Status</span><span class="detail-val">${d.status}</span></div>`;
                if(d.days != null) h += `<div class="detail-row"><span>Age</span><span class="detail-val">${d.days} days (${d.years} yrs)</span></div>`;
                if(d.created) h += `<div class="detail-row"><span>Created</span><span class="detail-val">${d.created}</span></div>`;
            } else if (key === 'dns') {
                if(d.ip) h += `<div class="detail-row"><span>IP/A Record</span><span class="detail-val" style="color:${typeof d.ip === 'string' && d.ip.includes('NXDOMAIN') ? 'var(--danger)' : 'var(--text)'}">${typeof d.ip === 'object' ? d.ip.join(', ') : d.ip}</span></div>`;
                if(d.spf) h += `<div class="detail-row"><span>SPF</span><span class="detail-val">${d.spf}</span></div>`;
                if(d.dmarc) h += `<div class="detail-row"><span>DMARC</span><span class="detail-val">${d.dmarc}</span></div>`;
                if(d.mx) h += `<div class="detail-row"><span>MX Record</span><span class="detail-val">${d.mx}</span></div>`;
            } else if (key === 'patterns') {
                if(d.findings && d.findings.length > 0) { d.findings.forEach(f => h += `<div style="color:var(--warn);margin-bottom:6px;">${f}</div>`); }
                else { h += `<div style="color:var(--success);">✅ No suspicious patterns detected</div>`; }
            }
            return h;
        }

        function clearAll() { document.getElementById('urlInput').value = ''; clearUI(); }

        function clearUI() {
            document.getElementById('progressWrapper').style.display = 'none';
            document.getElementById('scoreDisplay').style.display = 'none';
            document.getElementById('logBox').style.display = 'none';
            document.getElementById('logBox').innerHTML = '';
            document.getElementById('pFill').style.width = '0%';
            document.querySelectorAll('.btn-sm').forEach(b => b.style.display = 'none');
            ['google', 'vt', 'vt_url', 'urlscan', 'ssl', 'whois', 'dns', 'patterns'].forEach(c => {
                document.getElementById('c-'+c).className = 'card';
                document.getElementById('st-'+c).className = 'status-badge s-loading';
                document.getElementById('st-'+c).innerText = 'Waiting';
                document.getElementById('d-'+c).innerHTML = '';
            });
        }

        function copyLink() {
            navigator.clipboard.writeText(currentUrl);
            const btn = document.getElementById('copyBtn');
            const original = btn.innerText; btn.innerText = '✅ Copied!'; btn.style.color = 'var(--success)';
            setTimeout(() => { btn.innerText = original; btn.style.color = ''; }, 2000);
        }

        function download(type) { if(currentSid) window.open(`/download/${type}/${currentSid}`, '_blank'); }
        
        document.getElementById('urlInput').addEventListener('keypress', function(e) { if (e.key === 'Enter') startScan(); });
    </script>
</body>
</html>"""

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️ ULTIMATE PRO PHISHING ANALYZER")
    print("="*60)
    print("✅ Fixed: Dead domain (NXDOMAIN) = CRITICAL threat")
    print("✅ Fixed: SSL hides raw socket errors")
    print("✅ Fixed: URLScan handles long URLs gracefully")
    print("✅ Fixed: Scoring: Dead + VT Malicious = HIGH RISK")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, threaded=True)
