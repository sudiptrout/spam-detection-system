from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import re


APP_DIR = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT = 4173


RULES = [
    {
        "label": "Requests passwords, card details, or verification codes",
        "weight": 24,
        "severity": "danger",
        "pattern": re.compile(r"\b(password|passcode|otp|verification code|card details|cvv|social security|pin)\b", re.I),
    },
    {
        "label": "Uses urgent pressure or account suspension threats",
        "weight": 19,
        "severity": "danger",
        "pattern": re.compile(r"\b(urgent|immediately|within \d+ minutes|act now|final notice|suspended|locked|expire[sd]? today)\b", re.I),
    },
    {
        "label": "Contains a link with suspicious wording",
        "weight": 17,
        "severity": "warning",
        "custom": "suspicious_link",
    },
    {
        "label": "Mentions prizes, refunds, winnings, or money release",
        "weight": 16,
        "severity": "warning",
        "pattern": re.compile(r"\b(prize|winner|won|refund|cash|bonus|reward|lottery|payment release|wire transfer)\b", re.I),
    },
    {
        "label": "Asks for payment, fees, or shipping charges",
        "weight": 14,
        "severity": "warning",
        "pattern": re.compile(r"\b(pay|payment|fee|fees|shipping charge|unpaid|invoice overdue)\b", re.I),
    },
    {
        "label": "Sender domain looks generic or mismatched",
        "weight": 13,
        "severity": "warning",
        "custom": "sender_domain",
    },
    {
        "label": "Greeting is vague or impersonal",
        "weight": 8,
        "severity": "notice",
        "pattern": re.compile(r"\b(dear customer|dear user|hello user|valued customer)\b", re.I),
    },
    {
        "label": "Message has unusual capitalization or repeated punctuation",
        "weight": 8,
        "severity": "notice",
        "pattern": re.compile(r"[!?]{3,}|[A-Z]{6,}"),
    },
    {
        "label": "Short message relies on a link or command",
        "weight": 7,
        "severity": "notice",
        "custom": "short_link_command",
    },
]


def clamp(value, minimum=0, maximum=100):
    return min(max(value, minimum), maximum)


def custom_rule_matches(rule_name, text, sender, body):
    if rule_name == "suspicious_link":
        has_link = re.search(r"(http|www\.)", text, re.I)
        has_suspicious_words = re.search(r"(http|www\.|\.click|\.top|\.xyz|login|verify|prize|claim|track)", text, re.I)
        return bool(has_link and has_suspicious_words)

    if rule_name == "sender_domain":
        value = sender.lower()
        generic = re.search(r"@(gmail|yahoo|outlook|hotmail)\.", value)
        mismatch = re.search(r"(login|verify|secure|alert|support|billing)", value) and re.search(r"(example|\.info|\.top|\.xyz|\.click)", value)
        return bool(generic or mismatch)

    if rule_name == "short_link_command":
        word_count = len(body.strip().split())
        return word_count < 18 and bool(re.search(r"(http|click|reply|call now)", text, re.I))

    return False


def positive_signal_reduction(text, sender, body):
    reduction = 0

    if "@" in sender and not re.search(r"(login|verify|secure|prize|claim)", sender, re.I):
        reduction += 5

    if len(body.split()) > 24 and not re.search(r"(http|www\.)", text, re.I):
        reduction += 7

    if re.search(r"\b(meeting|timeline|attached|shared folder|review|planning|thanks|regards)\b", text, re.I):
        reduction += 6

    return reduction


def analyze_message(payload):
    sender = str(payload.get("sender", "")).strip()
    subject = str(payload.get("subject", "")).strip()
    body = str(payload.get("message", "")).strip()
    text = f"{sender} {subject} {body}"

    matches = []
    for rule in RULES:
        if "pattern" in rule:
            matched = bool(rule["pattern"].search(text))
        else:
            matched = custom_rule_matches(rule["custom"], text, sender, body)

        if matched:
            matches.append(
                {
                    "label": rule["label"],
                    "severity": rule["severity"],
                    "weight": rule["weight"],
                }
            )

    raw_score = sum(item["weight"] for item in matches) - positive_signal_reduction(text, sender, body)
    score = clamp(raw_score)

    verdict = "Likely safe"
    summary = "This message has a low spam pattern score."
    action = "Reply only through your usual trusted channel if anything still feels unusual."

    if not text.strip():
        verdict = "Ready to scan"
        summary = "Enter a message and run the analyzer."
        action = "Keep the original message available before making a decision."
    elif score >= 70:
        verdict = "High spam risk"
        summary = "Multiple high-risk patterns were found."
        action = "Do not click links or share information. Verify through the official website or saved contact."
    elif score >= 40:
        verdict = "Suspicious"
        summary = "Some warning signs need a closer look."
        action = "Avoid links in the message. Confirm the request from a trusted source first."
    elif score >= 18:
        verdict = "Needs review"
        summary = "The message has a few mild spam indicators."
        action = "Check the sender and destination links before responding."

    return {
        "score": score,
        "verdict": verdict,
        "summary": summary,
        "action": action,
        "signals": matches,
    }


class SpamDetectionHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(APP_DIR), **kwargs)

    def do_POST(self):
        if self.path != "/api/analyze":
            self.send_error(404, "Not found")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            payload = json.loads(body or "{}")
            response = analyze_message(payload)
            self.send_json(200, response)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON payload"})

    def send_json(self, status, payload):
        content = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def run():
    server = ThreadingHTTPServer((HOST, PORT), SpamDetectionHandler)
    print(f"Spam Detection App running at http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run()
