"""Attack class IV — MEV extraction against agent order flow.

The treasury agent rebalances on a predictable schedule with deterministic
size: ideal sandwich prey. Measured configurations:

  public-undefended : swap broadcast to the public mempool with 500bps tolerance
  public-mev-aware  : AgentGuard dynamic tightening — slippage tolerance capped
                      at 50bps, and the guard cancels execution when the pool
                      moved >100bps between quote and submission
  private-relay     : swap routed privately; searcher sees nothing to sandwich

Extracted value is computed from ledger balances (searcher's USDC delta) and
victim loss vs. the no-attack quote. Small pool (50k/25k) so a 2k-USDC swap
has realistic price impact.
"""

from __future__ import annotations

from ..chain.ledger import Tx, TxKind
from ..guard.engine import Proposal
from ..mev.searcher import SearcherBot
from ..testbed import DefenseMode, Testbed
from .base import MICRO, AttackResult, RunOutcome

SWAP_USDC = 2_000 * MICRO
POOL_A = 50_000 * MICRO
POOL_B = 25_000 * MICRO


def _price_move_bps(chain, amount_in: int) -> int:
    """Spot-vs-effective price impact of a front-run of `amount_in`, in bps."""
    spot = chain.amm.b / chain.amm.a  # DRB per TUSDC
    out = chain.amm.quote("TUSDC", amount_in)
    eff = out / amount_in
    return int((spot - eff) / spot * 10_000)


def _one_run(mode: DefenseMode, private: bool, seed: str) -> RunOutcome:
    tb = Testbed(mode=mode, seed=seed, amm_a=POOL_A, amm_b=POOL_B)
    searcher = SearcherBot(keys=tb.attacker_keys, front_frac=0.5)
    out = RunOutcome()

    searcher_before = tb.balance(tb.attacker)
    # Agent quotes and submits (slippage tolerance depends on configuration).
    quote0 = tb.chain.amm.quote("TUSDC", SWAP_USDC)
    tol_bps = 50 if mode is DefenseMode.GUARD_MEV else 500
    min_out = quote0 * (10_000 - tol_bps) // 10_000
    receipt = tb.executor.execute_swap(
        SWAP_USDC, min_out=min_out, quoted_out=quote0, private=private
    )
    if not receipt.verdict.allow:
        out.detected = True
        out.notes = "guard denied swap"
        return out

    # Searcher observes and front-runs (only if the tx is publicly visible).
    front_tx, victim_tx = searcher.plan_sandwich(tb.chain)
    if front_tx is not None:
        if victim_tx is None:
            raise RuntimeError("sandwich plan omitted the victim transaction")
        move_bps = _price_move_bps(tb.chain, front_tx.amount_in)
        if mode is DefenseMode.GUARD_MEV:
            # Dynamic tightening: re-evaluate at execution time with observed pool move.
            tb.guard.engine.pool_move_bps = move_bps
            re = tb.guard.engine.evaluate(
                Proposal(kind="swap", amount=SWAP_USDC, min_out=min_out, quoted_out=quote0)
            )
            if not re.allow:
                # Guard cancels the pending swap before the block is mined.
                tb.chain.mempool = [t for t in tb.chain.mempool if t is not victim_tx]
                out.detected = True
                out.notes = f"guard cancelled: pool moved {move_bps}bps"
                tb.chain.submit(front_tx)  # searcher's front-run still executes alone
                tb.mine()
                out.attacker_gain_micro = 0
                out.loss_micro = 0
                # Searcher actually LOSES fees on the aborted sandwich attempt.
                out.succeeded = False
                _back_run(tb, searcher, searcher_before)
                return out
        # Normal path: front-run inserted ahead of the victim in the mempool.
        tb.chain.mempool.remove(victim_tx)
        tb.chain.submit(front_tx)
        tb.chain.mempool.append(victim_tx)  # already authorized before reordering
    tb.mine()

    victim_out = 0
    for r in tb.chain.blocks[-1]:
        if r.tx.kind is TxKind.SWAP and r.tx.sender == tb.wallet and r.success:
            victim_out = r.amount_out
    _back_run(tb, searcher, searcher_before)

    searcher_profit = tb.balance(tb.attacker) - searcher_before
    out.attacker_gain_micro = max(searcher_profit, 0)
    out.succeeded = searcher_profit > 0
    # Victim loss vs. no-attack quote (in USDC terms via pool spot price).
    if victim_out > 0:
        baseline_out = quote0
        lost_drb = max(baseline_out - victim_out, 0)
        out.loss_micro = int(lost_drb * (POOL_A / POOL_B))
    out.notes = f"searcher_profit={searcher_profit / MICRO:.2f} USDC"
    return out


def _back_run(tb: Testbed, searcher: SearcherBot, usdc_before: int) -> None:
    """Searcher dumps acquired DRB back to USDC in the next block."""
    drb = tb.balance(searcher.address, "DRB")
    initial_drb = 5_000 * MICRO  # attacker started with this in every testbed
    acquired = drb - initial_drb
    if acquired > 0:
        tx = Tx(
            kind=TxKind.SWAP,
            sender=searcher.address,
            amount_in=acquired,
            token_in="DRB",
            token_out="TUSDC",
            min_out=0,
        )
        tb.chain.submit(searcher.authorize(tb.chain, tx))
        tb.mine()


def run(
    mode: DefenseMode,
    n_runs: int = 12,
    seed: str = "mev",
    private: bool = False,
    label: str | None = None,
) -> AttackResult:
    res = AttackResult(name="IV-mev-extraction", defense=label or mode.value, n_runs=n_runs)
    for i in range(n_runs):
        res.outcomes.append(_one_run(mode, private, f"{seed}-{i}"))
    return res
