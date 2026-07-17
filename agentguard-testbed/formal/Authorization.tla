--------------------------- MODULE Authorization ---------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS Proposals, UnitAmount, Cap

VARIABLES state, reservations, settledSpend, authorized

vars == <<state, reservations, settledSpend, authorized>>

Amount(p) == UnitAmount

RECURSIVE SumProposals(_)
SumProposals(S) ==
    IF S = {}
    THEN 0
    ELSE LET p == CHOOSE item \in S: TRUE
         IN Amount(p) + SumProposals(S \ {p})

ReservedSpend == SumProposals(reservations)
ProtectedStates == {"RESERVED", "SIGNED", "SUBMITTED"}
SignedStates == {"SIGNED", "SUBMITTED", "SETTLED"}
States == {
    "PROPOSED", "RESERVED", "SIGNED", "SUBMITTED", "SETTLED",
    "DENIED", "REVERTED", "EXPIRED"
}

TypeOK ==
    /\ state \in [Proposals -> States]
    /\ reservations \subseteq Proposals
    /\ settledSpend \in Nat
    /\ authorized \subseteq Proposals

Init ==
    /\ state = [p \in Proposals |-> "PROPOSED"]
    /\ reservations = {}
    /\ settledSpend = 0
    /\ authorized = {}

Reserve(p) ==
    /\ state[p] = "PROPOSED"
    /\ ReservedSpend + settledSpend + Amount(p) <= Cap
    /\ state' = [state EXCEPT ![p] = "RESERVED"]
    /\ reservations' = reservations \cup {p}
    /\ UNCHANGED <<settledSpend, authorized>>

Deny(p) ==
    /\ state[p] = "PROPOSED"
    /\ ReservedSpend + settledSpend + Amount(p) > Cap
    /\ state' = [state EXCEPT ![p] = "DENIED"]
    /\ UNCHANGED <<reservations, settledSpend, authorized>>

Sign(p) ==
    /\ state[p] = "RESERVED"
    /\ state' = [state EXCEPT ![p] = "SIGNED"]
    /\ authorized' = authorized \cup {p}
    /\ UNCHANGED <<reservations, settledSpend>>

Submit(p) ==
    /\ state[p] = "SIGNED"
    /\ state' = [state EXCEPT ![p] = "SUBMITTED"]
    /\ UNCHANGED <<reservations, settledSpend, authorized>>

Settle(p) ==
    /\ state[p] = "SUBMITTED"
    /\ state' = [state EXCEPT ![p] = "SETTLED"]
    /\ reservations' = reservations \ {p}
    /\ settledSpend' = settledSpend + Amount(p)
    /\ UNCHANGED authorized

Revert(p) ==
    /\ state[p] = "SUBMITTED"
    /\ state' = [state EXCEPT ![p] = "REVERTED"]
    /\ reservations' = reservations \ {p}
    /\ UNCHANGED <<settledSpend, authorized>>

Expire(p) ==
    /\ state[p] \in {"PROPOSED", "RESERVED", "SIGNED"}
    /\ state' = [state EXCEPT ![p] = "EXPIRED"]
    /\ reservations' = reservations \ {p}
    /\ UNCHANGED <<settledSpend, authorized>>

Next ==
    \E p \in Proposals:
        Reserve(p) \/ Deny(p) \/ Sign(p) \/ Submit(p) \/
        Settle(p) \/ Revert(p) \/ Expire(p)

Spec == Init /\ [][Next]_vars

NoSigningWithoutAuthorization ==
    \A p \in Proposals: state[p] \in SignedStates => p \in authorized

NoOverspend == ReservedSpend + settledSpend <= Cap

ReservationSafety ==
    \A p \in Proposals: (p \in reservations) <=> (state[p] \in ProtectedStates)

=============================================================================
