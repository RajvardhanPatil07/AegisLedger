"""LanguageAgent: the injected surface. Reads untrusted content (web pages,
tool outputs, peer messages) and emits instructions — including attacker-
planted ones when susceptible. Holds no wallet authority by design.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .base import Sanitizer, PaymentInstruction, extract_instructions


@dataclass
class LanguageAgent:
    name: str = "language-agent"
    susceptible: bool = True
    sanitizer: Sanitizer = field(default_factory=Sanitizer)
    attacker_address: str = "0xattacker"
    log: list[str] = field(default_factory=list)

    def process_content(self, content: str) -> list[PaymentInstruction]:
        cleaned, survived = self.sanitizer.clean(content)
        instrs = extract_instructions(cleaned, susceptible=self.susceptible,
                                      attacker_address=self.attacker_address)
        for i in instrs:
            self.log.append(f"instruction emitted: {i.purpose} amount={i.amount} to={i.to}")
        if not survived:
            self.log.append("sanitizer redacted plaintext injection")
        return instrs
