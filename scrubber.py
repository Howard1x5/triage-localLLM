import re

# RFC 1918 + loopback internal IP patterns
_INTERNAL_IP = re.compile(
    r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
)
_EMAIL = re.compile(r'\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b')
_AWS_ACCOUNT = re.compile(r'\b\d{12}\b')
_AWS_ARN = re.compile(r'arn:aws:[^\s"\']+')
_USERNAME_PATH = re.compile(r'(?<=/home/|/Users/|C:\\Users\\)([^\s/\\]+)')
_HOSTNAME_INTERNAL = re.compile(r'\b[a-zA-Z0-9-]{3,}\.(?:local|internal|corp|lan|intranet)\b')
_SESSION_TOKEN = re.compile(r'\b[A-Za-z0-9+/]{40,}={0,2}\b')

_ip_counter = {}
_user_counter = {}


def scrub(text: str) -> tuple[str, dict]:
    """Return (scrubbed_text, replacement_map) so caller can un-redact if needed."""
    replacements = {}

    def _replace_ip(m):
        ip = m.group(0)
        if ip not in _ip_counter:
            _ip_counter[ip] = len(_ip_counter) + 1
        token = f"[INTERNAL-IP-{_ip_counter[ip]}]"
        replacements[token] = ip
        return token

    def _replace_user(m):
        user = m.group(1)
        if user not in _user_counter:
            _user_counter[user] = len(_user_counter) + 1
        token = f"[USER-{_user_counter[user]}]"
        replacements[token] = user
        return m.group(0).replace(user, token)

    text = _INTERNAL_IP.sub(_replace_ip, text)
    text = _EMAIL.sub("[EMAIL-REDACTED]", text)
    text = _AWS_ARN.sub("[AWS-ARN-REDACTED]", text)
    text = _AWS_ACCOUNT.sub("[AWS-ACCOUNT-REDACTED]", text)
    text = _USERNAME_PATH.sub(_replace_user, text)
    text = _HOSTNAME_INTERNAL.sub("[INTERNAL-HOST]", text)
    text = _SESSION_TOKEN.sub("[TOKEN-REDACTED]", text)

    return text, replacements
