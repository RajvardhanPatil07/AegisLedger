"""Attack result types and shared metric computation."""

from __future__ import annotations

from dataclasses import dataclass, field

MICRO = 1_000_000


@dataclass
class RunOutcome:
    attempted: bool = True
    succeeded: bool = False  # attacker goal achieved
    loss_micro: int = 0  # victim loss in micro-USDC equivalent
    attacker_gain_micro: int = 0
    detected: bool = False  # denied / reverted / flagged
    notes: str = ""


@dataclass
class AttackResult:
    name: str
    defense: str
    n_runs: int
    outcomes: list[RunOutcome] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        return sum(1 for o in self.outcomes if o.succeeded) / max(len(self.outcomes), 1)

    @property
    def total_loss_micro(self) -> int:
        return sum(o.loss_micro for o in self.outcomes)

    @property
    def avg_loss_usdc(self) -> float:
        return self.total_loss_micro / MICRO / max(len(self.outcomes), 1)

    @property
    def detection_rate(self) -> float:
        return sum(1 for o in self.outcomes if o.detected) / max(len(self.outcomes), 1)

    def row(self) -> dict:
        return {
            "attack": self.name,
            "defense": self.defense,
            "runs": self.n_runs,
            "success_rate": round(self.success_rate, 3),
            "avg_loss_usdc": round(self.avg_loss_usdc, 2),
            "detection_rate": round(self.detection_rate, 3),
        }
