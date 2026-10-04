"""
DecodeLabs - Cyber Security Project 3
Phishing Awareness Analysis (Phishing Triage Toolkit)

Author : Ahmad Nawaz

What it does:
  1. Reads an email/message (From, Reply-To, Subject, body, attachments)
  2. Finds suspicious links and keywords
  3. Lists every red flag found
  4. Explains why the message is unsafe
  5. Gives a triage decision:
       SAFE       -> Close
       SUSPICIOUS -> Warn User
       MALICIOUS  -> Block Domain & Escalate
"""

import re
from urllib.parse import urlparse

# ---------------------------------------------------------------- settings
TRUSTED_BRANDS = ["paypal", "amazon", "microsoft", "google", "apple",
                  "facebook", "netflix", "linkedin", "chatgpt"]
FREE_MAIL = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"]
RISKY_TLDS = [".xyz", ".top", ".click", ".tk", ".ml", ".gq", ".work", ".zip"]
BAD_EXT = [".exe", ".iso", ".img", ".js", ".scr", ".bat", ".cmd", ".vbs", ".hta", ".lnk",
           ".html", ".htm", ".ps1", ".msi", ".jar", ".dll", ".docm", ".xlsm"]
SECURITY_WORDS = ["secure", "login", "verify", "update", "account", "support", "billing"]

# Real domains a brand uses besides its main one (so they are not flagged).
BRAND_DOMAINS = {
    "facebook": ["facebookmail.com"],
    "microsoft": ["microsoftonline.com", "live.com", "office.com"],
    "google": ["googlemail.com"],
    "apple": ["icloud.com"],
    "linkedin": ["licdn.com"],
}

# Phrases that mean the opposite of a scam keyword ("Non-Urgent", "no action required").
SAFE_PHRASES_RE = re.compile(
    r"non-?urgent|not urgent|no (?:immediate )?action(?: is)?(?: required| needed)?", re.I)

KEYWORDS = {
    "Urgency": ["urgent", "immediately", "asap", "within 24 hours", "expires",
                "final notice", "act now", "account locked", "suspended"],
    "Fear / Threat": ["legal action", "terminated", "unauthorized", "security alert",
                      "compromised", "penalty", "overdue"],
    "Greed / Reward": ["you have won", "prize", "gift card", "free gift", "lottery", "reward"],
    "Sensitive info request": ["password", "otp", "verification code", "mfa code",
                               "credit card", "cvv", "pin", "bank details", "ssn"],
    "Secrecy / Bypass": ["confidential", "do not discuss", "bypass", "keep this between us"],
    "Callback (TOAD)": ["call us", "call now", "toll free", "1-800", "customer support number"],
    "QR code lure": ["scan the qr", "scan this code", "scan to unlock", "scan to verify"],
}

URL_RE = re.compile(r"https?://[^\s<>\"')]+|www\.[^\s<>\"')]+", re.I)
SHORT_RE = re.compile(r"\b(?:" + "|".join(re.escape(d) for d in SHORTENERS) + r")/[^\s<>\"')]+", re.I)


def find_links(text):
    """All URLs in the text, cleaned and without duplicates."""
    found = []
    spans = []
    for m in URL_RE.finditer(text):
        found.append(m.group())
        spans.append(m.span())
    for m in SHORT_RE.finditer(text):
        # skip shortener links that are already part of a full URL
        if not any(a <= m.start() and m.end() <= b for a, b in spans):
            found.append(m.group())
    clean, seen = [], set()
    for link in found:
        link = link.rstrip(".,;:!?")
        if link.lower() not in seen:
            seen.add(link.lower())
            clean.append(link)
    return clean


# ---------------------------------------------------------------- helpers
MULTI_SUFFIX = ("co.uk", "org.uk", "com.pk", "org.pk", "edu.pk", "gov.pk",
                "com.au", "co.in", "com.br", "co.jp", "com.sa", "co.za")


def root_domain(host):
    """Registrable domain, e.g. www.paypal.co.uk -> paypal.co.uk."""
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def brand_in(domain, brand):
    """True only if the brand is a whole word in the domain (not 'pineapple')."""
    return brand in re.split(r"[^a-z0-9]+", domain.lower())


def is_real_brand(domain, brand):
    """True if the registrable domain is the brand's own (or a known alternate) domain."""
    root = root_domain(domain)
    return root.split(".")[0] == brand or root in BRAND_DOMAINS.get(brand, [])


def email_domain(address):
    return address.split("@")[-1].lower().strip(" >") if "@" in address else ""


def parse_header(raw, name):
    m = re.search(rf"^{name}:[ \t]*(.+)$", raw, re.I | re.M)
    return m.group(1).strip() if m else ""


def has_lookalike_chars(text):
    """Digits swapped for letters (amaz0n) or non-ASCII characters (Cyrillic a)."""
    if any(ord(c) > 127 for c in text):
        return True
    return any(re.search(p, text) for p in (r"amaz0n", r"paypa1", r"micr0soft",
                                             r"g00gle", r"faceb00k", r"app1e", r"netf1ix"))


# ---------------------------------------------------------------- link checks
def check_link(url):
    """Return a list of (flag, explanation) for one URL."""
    flags = []
    full = url if url.lower().startswith("http") else "http://" + url
    host = (urlparse(full).hostname or "").lower()
    root = root_domain(host)

    if url.lower().startswith("http://"):
        flags.append(("No HTTPS", f"{url} is not encrypted"))
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        flags.append(("IP address link", f"{host} is a raw IP, not a real domain"))
    if "@" in urlparse(full).netloc:
        flags.append(("'@' in URL", "Everything before @ is ignored by the browser, hides the real site"))
    if host in SHORTENERS:
        flags.append(("URL shortener", f"{host} hides the final destination"))
    if any(host.endswith(t) for t in RISKY_TLDS):
        flags.append(("Risky TLD", f"{root} uses a TLD often abused for phishing"))
    if has_lookalike_chars(host):
        flags.append(("Lookalike domain", f"{host} imitates a real brand (typosquatting/homoglyph)"))
    if host.startswith("xn--") or ".xn--" in host:
        flags.append(("Punycode domain", f"{host} may hide non-English look-alike characters"))
    for brand in TRUSTED_BRANDS:
        if brand_in(host, brand) and not is_real_brand(host, brand):
            if brand_in(root, brand):
                flags.append(("Combosquatting", f"{root} adds extra words to brand '{brand}'"))
            else:
                flags.append(("Subdomain trap", f"'{brand}' appears in {host} but the real root domain is {root}"))
            break
    if host.count(".") >= 4:
        flags.append(("Too many subdomains", f"{host} is overly nested"))
    return flags


# ---------------------------------------------------------------- main analyzer
def analyze(raw):
    """Analyze one email. Returns a dict with score, verdict, flags and reasons."""
    flags = []      # list of (category, detail, points)

    if len(raw.strip()) < 5:
        return {"subject": "", "sender": "", "score": 0, "verdict": "NO INPUT",
                "action": "Nothing to analyze - paste the full email", "flags": [], "links": []}

    sender = parse_header(raw, "From")
    reply_to = parse_header(raw, "Reply-To")
    subject = parse_header(raw, "Subject")
    attach = parse_header(raw, "Attachment")
    body = SAFE_PHRASES_RE.sub(" ", raw.lower())

    # --- sender checks
    s_domain = email_domain(sender)
    display = re.sub(r"<.*?>", "", sender).strip().lower()
    if s_domain in FREE_MAIL and re.search(
            r"\b(ceo|cfo|support|security|hr|admin|bank|director|it|helpdesk|billing)\b", display):
        flags.append(("Sender-domain mismatch",
                      f"'{display}' claims authority but uses a free mail address ({s_domain})", 3))
    for brand in TRUSTED_BRANDS:
        if (brand_in(display, brand) and s_domain and not brand_in(s_domain, brand)
                and not is_real_brand(s_domain, brand)):
            flags.append(("Sender-domain mismatch",
                          f"Display name says '{brand}' but the address is from {s_domain}", 3))
            break
    for brand in TRUSTED_BRANDS:
        if brand_in(s_domain, brand) and not is_real_brand(s_domain, brand):
            flags.append(("Combosquatting sender",
                          f"{s_domain} looks like '{brand}' but is not the real {brand} domain", 3))
            break
    if has_lookalike_chars(s_domain):
        flags.append(("Lookalike sender domain", f"{s_domain} imitates a real brand", 3))
    if any(s_domain.endswith(t) for t in RISKY_TLDS):
        flags.append(("Suspicious sender domain", f"{s_domain} uses a TLD often abused for phishing", 2))
    if reply_to and email_domain(reply_to) != s_domain:
        flags.append(("Reply-To mismatch",
                      f"Replies go to {email_domain(reply_to)} instead of {s_domain}", 2))
    if re.search(r"^subject:[ \t]*(fw|fwd):", raw, re.I | re.M):
        flags.append(("Fake forwarded chain", "FW: subject on a conversation you were never part of", 1))
    if re.search(r"dear (customer|user|client|sir|madam|account holder)", body):
        flags.append(("Generic greeting", "Real companies usually use your actual name", 1))

    # --- keyword checks
    for category, words in KEYWORDS.items():
        found = [w for w in words if re.search(r"\b" + re.escape(w) + r"\b", body)]
        if found:
            pts = 2 if category in ("Sensitive info request", "Secrecy / Bypass",
                                    "Callback (TOAD)", "QR code lure") else 1
            flags.append((f"Keyword - {category}", ", ".join(found), pts))

    # --- link checks
    links = find_links(raw)
    link_flags = []
    for link in links:
        for name, why in check_link(link):
            link_flags.append((name, why, 2))
    flags.extend(link_flags)

    # --- attachment check
    for name in re.split(r"[,;]", attach):
        name = name.strip()
        for ext in BAD_EXT:
            if name.lower().endswith(ext):
                flags.append(("Dangerous attachment", f"{name} uses risky extension {ext}", 3))
                break

    score = sum(f[2] for f in flags)
    if score >= 7:
        verdict, action = "MALICIOUS", "Block Domain & Escalate to Security Team"
    elif score >= 3:
        verdict, action = "SUSPICIOUS", "Warn User (do not click, verify via phone/known channel)"
    else:
        verdict, action = "SAFE", "Close"

    return {"subject": subject, "sender": sender, "score": score, "verdict": verdict,
            "action": action, "flags": flags, "links": links}


def explain(result):
    """Short human explanation of why the message is (un)safe."""
    cats = {f[0] for f in result["flags"]}
    if result["verdict"] == "NO INPUT":
        return "The message was empty, so it cannot be judged."
    if result["verdict"] == "SAFE":
        return "No meaningful red flags found. Normal, low-urgency message with no risky links."
    reasons = []
    if any(k in c for c in cats for k in ("Sender", "Reply-To", "sender")):
        reasons.append("the sender is pretending to be someone they are not")
    if any("Keyword - Urgency" in c or "Keyword - Fear" in c for c in cats):
        reasons.append("it uses urgency/fear to make you act without thinking")
    if any(c in cats for c in ("Keyword - Sensitive info request", "Keyword - Secrecy / Bypass")):
        reasons.append("it asks for secrets or tells you to skip normal procedure")
    if result["links"] and any(c for c in cats if c in (
            "Subdomain trap", "Combosquatting", "Lookalike domain", "URL shortener",
            "IP address link", "Risky TLD", "No HTTPS", "'@' in URL", "Punycode domain",
            "Too many subdomains")):
        reasons.append("its links point to a fake or hidden website")
    if "Dangerous attachment" in cats:
        reasons.append("the attachment can run malware")
    if "Keyword - Callback (TOAD)" in cats:
        reasons.append("it pushes you to call a fake support number")
    if "Keyword - QR code lure" in cats:
        reasons.append("it uses a QR code to bypass link filters")
    if not reasons:
        reasons.append("several small warning signs add up")
    return "Unsafe because " + "; ".join(reasons) + "."


def report(result):
    line = "=" * 64
    print(line)
    print(f"Subject : {result['subject'] or '(none)'}")
    print(f"From    : {result['sender'] or '(none)'}")
    print(f"Links   : {len(result['links'])} found")
    for l in result["links"]:
        print(f"          - {l}")
    print("-" * 64)
    if result["flags"]:
        print("RED FLAGS:")
        for i, (cat, detail, pts) in enumerate(result["flags"], 1):
            print(f"  {i}. [{cat}] {detail}  (+{pts})")
    else:
        print("RED FLAGS: none")
    print("-" * 64)
    print(f"Risk score : {result['score']}")
    print(f"Verdict    : {result['verdict']}")
    print(f"Action     : {result['action']}")
    print(f"Why        : {explain(result)}")
    print(line + "\n")


# ---------------------------------------------------------------- sample emails
SAMPLES = {
    "1": ("Fake Microsoft security alert", """From: Microsoft Support <support@logins-updates.com>
Subject: FW: Urgent: Your Account Security Alert
Attachment: Security_Update_2026.iso

Dear customer,
Unauthorized sign-in detected. Your account will be suspended within 24 hours.
Verify your password immediately: http://microsoft.login-update.com/verify
"""),
    "2": ("CEO wire transfer (BEC)", """From: CEO - STRICTLY CONFIDENTIAL <ceo.urgent@gmail.com>
Reply-To: ceo.payments@executive-update.xyz
Subject: IMMEDIATE ACTION REQUIRED: Transfer Authorization

Process the attached wire transfer immediately. This is confidential.
Do not discuss with anyone. Bypass standard procedure. Send bank details back asap.
"""),
    "3": ("Fake ChatGPT payment failure", """From: ChatGPT Billing <billing@chatgpt-secure-billing.com>
Subject: Urgent: Payment Failure

Dear user, your subscription payment failed.
Update your billing information to avoid service interruption:
https://bit.ly/3xUpd4te
"""),
    "4": ("Callback phishing (TOAD)", """From: Microsoft Billing <renewals@mail-notice.top>
Subject: Microsoft Subscription Renewal

Payment overdue: $190.00 charged. To cancel immediately call us on 1-800-555-0199.
"""),
    "5": ("Legit project update", """From: Sarah Lee <sarah.lee@company.com>
Subject: Q3 Project Status Update - Non-Urgent
Attachment: Q3_Status.pdf

Hi Team,
Please review the attached project status for Q3 at your earliest convenience.
No immediate action is required.
Thanks,
Sarah
"""),
}


# ---------------------------------------------------------------- menu
def read_multiline():
    print("Paste the email (From:/Reply-To:/Subject:/Attachment: headers first).")
    print("Type END on a new line when finished.")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().upper() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


def main():
    print("DecodeLabs | Project 3 | Phishing Triage Toolkit\n")
    while True:
        print("1) Analyze built-in sample emails")
        print("2) Analyze my own pasted email")
        print("3) Analyze an email from a .txt file")
        print("4) Exit")
        try:
            choice = input("Choose: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if choice == "1":
            for key, (title, mail) in SAMPLES.items():
                print(f"\n>>> Sample {key}: {title}")
                report(analyze(mail))
        elif choice == "2":
            report(analyze(read_multiline()))
        elif choice == "3":
            path = input("File path: ").strip().strip('"')
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    report(analyze(f.read()))
            except OSError as err:
                print(f"Could not open file: {err}\n")
        elif choice == "4":
            print("Stay safe. Pause, Verify, Report.")
            break
        else:
            print("Invalid choice.\n")


if __name__ == "__main__":
    main()
