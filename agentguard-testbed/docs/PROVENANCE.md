# Source and asset provenance

The machine-readable [provenance inventory](provenance.json) classifies every
tracked file and material that remains relevant in public Git history. It is an
audit control, not a declaration that all material is cleared for publication.

Run `make provenance` to validate schema, local evidence paths, and complete
coverage of the current Git index. Run
`python scripts/check_provenance_inventory.py --require-release-ready` before a
public release. The second command intentionally fails while any distributable
entry has `owner_confirmation_required` status.

## Current blockers

- The repository owner must confirm authorship, copyright ownership, and the
  intended Apache-2.0 grant for repository-authored code and documentation.
- The research manuscript needs a source/citation review and an explicit
  publication decision.
- Every research figure needs its source data, generation method, and reuse
  rights recorded. A PNG in the repository is not sufficient provenance.
- `Agent-Wallet-Security-Project-Master-Prompt.md` was deleted from the working
  tree but remains in Git history. It contains novelty, patent, and public
  disclosure claims, so deleting the current file does not clear the history.

To clear an entry, replace `owner_confirmation_required` with `verified` only
after adding durable evidence to that entry. If material cannot be cleared,
remove or replace it and decide whether public Git history must be rewritten
before publication. History rewriting is destructive and requires a separate,
explicit owner decision and coordination with every clone or fork.

Dependency license and vulnerability evidence is generated separately through
the Rust license policy, Python/npm audits, and container CycloneDX SBOM gates.
Those controls do not establish ownership of the repository's manuscript,
figures, or historical content.
