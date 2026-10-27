"""Manual authentication by default; opt-in empty-response sequences for scan/push flows."""
import re


class AuthFlow:
    def __init__(self, settings):
        self.settings = settings
        self.buffer = ''
        self.urls = []
        self.prompt = None
        self.sequence = None
        self.responses_sent = 0
        self.redactions = []

    def redact(self, value):
        for secret in self.redactions:
            value = value.replace(secret, '[REDACTED]')
        return value

    def feed(self, text):
        self.buffer = (self.buffer + text)[-16384:]
        self.urls = list(dict.fromkeys(m.group(0) for m in re.finditer(self.settings['url_pattern'], self.buffer)))[-6:]
        self.urls = [url for url in self.urls if isinstance(url, str) and url.startswith('https://')]
        rules = self.settings['confirm_empty_prompts']
        if self.sequence is not None and self.sequence < len(rules):
            if re.search(rules[self.sequence], self.buffer):
                self.sequence += 1
                self.responses_sent += 1
                self.buffer = ''
                self.prompt = None
                return 'empty'
        last_line = self.buffer.rstrip('\r\n').rsplit('\n', 1)[-1]
        match = re.search(self.settings['prompt_pattern'], last_line)
        self.prompt = match.group(0).strip() if match else None
        if rules and self.sequence is None and re.search(rules[0], self.buffer):
            self.prompt = re.search(rules[0], self.buffer).group(0).strip()
            return 'confirmation'
        if self.prompt:
            return 'prompt'
        if re.search(self.settings['shell_prompt_pattern'], self.buffer):
            return 'shell'
        return None

    def confirm(self):
        rules = self.settings['confirm_empty_prompts']
        if not rules or self.sequence is not None or not re.search(rules[0], self.buffer):
            raise ValueError('No configured confirmation sequence is pending')
        self.sequence = 1
        self.responses_sent += 1
        self.buffer = ''
        self.prompt = None

    def respond(self, value):
        if '\n' in value or '\r' in value or '\x00' in value:
            raise ValueError('Authentication responses must be a single line')
        if value:
            self.redactions.append(value)
        self.responses_sent += 1
        self.buffer = ''
        self.prompt = None
        self.sequence = None

    def public(self):
        return {'prompt': self.redact(self.prompt) if self.prompt else None, 'urls': self.urls,
                'recent_text': self.redact(self.buffer[-3000:]),
                'responses_sent': self.responses_sent,
                'configured_confirmation': bool(self.settings['confirm_empty_prompts'])}
