"""Scripted agent runtimes.

The testbed measures *system-layer* defenses (policy enforcement, attestation,
custody), so agents are deterministic scripts with a documented, configurable
injection-susceptibility: when untrusted content contains an instruction
pattern, a susceptible agent follows it. A "model-level defense" sanitizer
catches plaintext patterns but misses encoded payloads (Morse/base64) — mirroring
measured real-world behavior (e.g., the 2026 Morse-code wallet-drain incident).
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field


INJECTION_RE = re.compile(
    r"(transfer|send|pay)\s+(\d+(?:\.\d+)?)\s*(usdc|drb|tokens?)?\s*(?:to|towards)\s+"
    r"(0x[0-9a-fA-F]{6,40}|attacker)",
    re.IGNORECASE,
)

MORSE_MAP = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


def morse_decode(text: str) -> str:
    words = text.strip().split("   ")
    out_words = []
    for w in words:
        letters = [MORSE_MAP.get(c, "?") for c in w.split()]
        out_words.append("".join(letters))
    return " ".join(out_words)


def try_base64_decode(text: str) -> str | None:
    try:
        decoded = base64.b64decode(text, validate=True).decode(errors="strict")
        return decoded
    except Exception:
        return None


@dataclass
class Sanitizer:
    """Model-level defense: strips plaintext injection patterns. Known-bypassable
    by encoded payloads — this asymmetry is the measured property."""
    enabled: bool = False
    block_encoded: bool = False  # idealized upper-bound defense (not default)

    def clean(self, content: str) -> tuple[str, bool]:
        """Returns (possibly-sanitized content, instruction_survived)."""
        if not self.enabled:
            return content, True
        if INJECTION_RE.search(content):
            return INJECTION_RE.sub("[REDACTED]", content), False
        if self.block_encoded:
            return content, False  # idealized: also stops encoded channels
        # Default sanitizer cannot see encoded instructions: they survive.
        return content, True


@dataclass
class PaymentInstruction:
    amount: int            # micro-USDC
    to: str
    asset: str = "TUSDC"
    purpose: str = ""
    encoded_channel: bool = False


def extract_instructions(content: str, susceptible: bool = True,
                         attacker_address: str = "0xattacker") -> list[PaymentInstruction]:
    """Parse plaintext and encoded payment instructions from content."""
    if not susceptible:
        return []
    out: list[PaymentInstruction] = []
    for m in INJECTION_RE.finditer(content):
        amt = float(m.group(2))
        to = m.group(4)
        if to.lower() == "attacker":
            to = attacker_address
        out.append(PaymentInstruction(amount=int(amt * 1_000_000), to=to,
                                      purpose="injected-plaintext"))
    # Encoded channels
    morse = re.findall(r"(?:[.\-]{1,5}(?:\s+|$)){3,}", content)
    for seq in morse:
        decoded = morse_decode(seq)
        for m in INJECTION_RE.finditer(decoded):
            amt = float(m.group(2))
            to = m.group(4)
            if to.lower() == "attacker":
                to = attacker_address
            out.append(PaymentInstruction(amount=int(amt * 1_000_000), to=to,
                                          purpose="injected-morse",
                                          encoded_channel=True))
    b64 = re.findall(r"\b([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])", content)
    for cand in b64:
        decoded = try_base64_decode(cand)
        if not decoded:
            continue
        for m in INJECTION_RE.finditer(decoded):
            amt = float(m.group(2))
            to = m.group(4)
            if to.lower() == "attacker":
                to = attacker_address
            out.append(PaymentInstruction(amount=int(amt * 1_000_000), to=to,
                                          purpose="injected-b64", encoded_channel=True))
    return out
