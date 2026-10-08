# ===============================================================
#  PHISHING EMAIL ANALYZER  (beginner project)
#  Run it like this:   python analyzer.py test_emails
#  It reads every .eml file in the folder and gives each a score.
# ===============================================================

import os
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse

# ---------- LISTS OF SUSPICIOUS THINGS (you can add more!) ----------
URGENT_WORDS = ["urgent", "immediately", "suspended", "verify",
                "within 24 hours", "act now", "password", "confirm your",
                "gift card", "final warning", "blocked"]
BAD_ENDINGS = (".ru", ".xyz", ".top", ".click", ".tk")
BRANDS = {"paypal": "paypal.com", "amazon": "amazon.com",
          "microsoft": "microsoft.com", "google": "google.com"}


# ---------- STEP 3: OPEN AN EMAIL ----------
def load_email(path):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def get_body(msg):
    part = msg.get_body(preferencelist=("html", "plain"))
    return part.get_content() if part else ""


# ---------- STEP 4: FIND LINKS ----------
def get_links(body):
    pattern = r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>'
    return re.findall(pattern, body, re.I | re.S)


# ---------- STEP 5: THE RED-FLAG CHECKS ----------
def domain_of(address):
    return address.split("@")[-1].lower().strip(">")


def analyze(msg):
    findings = []  # each item = (points, reason)

    sender = parseaddr(msg["From"] or "")[1]
    sender_domain = domain_of(sender)
    reply_to = parseaddr(msg["Reply-To"] or "")[1]
    body = get_body(msg)

    # Check 1: Reply-To goes somewhere different?
    if reply_to and domain_of(reply_to) != sender_domain:
        findings.append((20, "Sender and Reply-To domains don't match"))

    # Check 2: Did the anti-fake checks fail?
    auth = (msg["Authentication-Results"] or "").lower()
    for check in ("spf", "dkim", "dmarc"):
        if f"{check}=fail" in auth or f"{check}=softfail" in auth:
            findings.append((15, f"{check.upper()} check FAILED"))

    # Check 3: Lookalike domain (paypa1 pretending to be paypal)
    normalized = sender_domain.replace("1", "l").replace("0", "o")
    for brand, official in BRANDS.items():
        if brand in normalized and not sender_domain.endswith(official):
            findings.append((25, f"Sender domain '{sender_domain}' imitates {brand}"))

    # Check 4: Pressure words
    text = (body + " " + (msg["Subject"] or "")).lower()
    hits = [w for w in URGENT_WORDS if w in text]
    if hits:
        findings.append((min(5 * len(hits), 20), f"Urgent language: {hits}"))

    # Check 5: Suspicious links
    for href, shown in get_links(body):
        host = urlparse(href).hostname or ""
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
            findings.append((25, f"Link points to a raw IP address: {href}"))
        if host.endswith(BAD_ENDINGS):
            findings.append((10, f"Link uses a suspicious ending: {host}"))
        if "." in shown and host and host not in shown.lower():
            findings.append((20, f"Link text '{shown.strip()}' hides real place '{host}'"))

    # Check 6 (bonus): scary attachment names mentioned
    if re.search(r"\.(zip|exe|scr|js)\b", text):
        findings.append((15, "Mentions a risky attachment type (.zip/.exe/.scr/.js)"))

    return findings


# ---------- STEP 6: SCORE AND VERDICT ----------
def score_email(path):
    msg = load_email(path)
    findings = analyze(msg)
    score = min(sum(p for p, _ in findings), 100)
    if score >= 60:
        verdict = "HIGH RISK"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"
    return msg, findings, score, verdict


def print_report(path):
    msg, findings, score, verdict = score_email(path)
    print(f"\nFile:    {os.path.basename(path)}")
    print(f"From:    {msg['From']}")
    print(f"Subject: {msg['Subject']}")
    print(f"Risk score: {score}/100  ->  {verdict}")
    for points, reason in findings:
        print(f"   - [+{points}] {reason}")


# ---------- RUN EVERYTHING ----------
def main():
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py test_emails")
        return

    # Collect .eml files (a folder name OR individual file names)
    files = []
    for arg in sys.argv[1:]:
        if os.path.isdir(arg):
            files += [os.path.join(arg, n) for n in sorted(os.listdir(arg)) if n.endswith(".eml")]
        else:
            files.append(arg)

    results = []
    for path in files:
        print_report(path)
        _, _, score, verdict = score_email(path)
        results.append((os.path.basename(path), score, verdict))

    # ----- Final summary table -----
    print("\n" + "=" * 62)
    print("SUMMARY")
    print("=" * 62)
    caught = missed = good = wrong = 0
    for name, score, verdict in results:
        flagged = verdict != "LOW RISK"
        if name.startswith("phish"):
            ok = flagged
            caught += ok
            missed += (not ok)
        elif name.startswith("legit"):
            ok = not flagged
            good += ok
            wrong += (not ok)
        else:
            ok = None
        mark = "" if ok is None else ("OK " if ok else "WRONG")
        print(f"{name:34} {score:3}  {verdict:11} {mark}")

    print("-" * 62)
    print(f"Phishing caught (flagged):        {caught}")
    print(f"Phishing MISSED (false negative): {missed}")
    print(f"Legit passed correctly:           {good}")
    print(f"Legit wrongly flagged (false +):  {wrong}")


main()
