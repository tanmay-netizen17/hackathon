"""
SentinelAI - Red Team Attacker
Generates adversarial payloads for robustness testing.
"""
import re, random

HOMOGLYPHS = {
    'a': ['а','ɑ','@'], 'e': ['е','ë','3'], 'i': ['і','1','l'],
    'o': ['о','0','ο'], 's': ['ѕ','$','5'], 'c': ['с','ϲ'],
    'p': ['р','ρ'], 'x': ['х','х'],
}

SYNONYM_MAP = {
    'suspended': ['paused','frozen','disabled'],
    'immediately': ['now','ASAP','urgently'],
    'verify': ['confirm','validate','check'],
}

class RedTeamAttacker:
    def obfuscate_text(self, text: str) -> str:
        words = text.split()
        for i, word in enumerate(words):
            if word.lower() in SYNONYM_MAP:
                words[i] = random.choice(SYNONYM_MAP[word.lower()])
        return " ".join(words)

    def generate_homoglyph_domain(self, domain: str) -> str:
        new_domain = ""
        for char in domain:
            if char in HOMOGLYPHS and random.random() > 0.7:
                new_domain += random.choice(HOMOGLYPHS[char])
            else:
                new_domain += char
        return new_domain

    def inject_zero_width(self, text: str) -> str:
        """Inserts invisible characters to break tokenization."""
        return "\u200b".join(text[i:i+3] for i in range(0, len(text), 3))
