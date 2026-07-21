from pathlib import Path

from scripts.check_release_metadata import collect_versions, validate_metadata


def write_candidate(
    root: Path,
    *,
    python_version: str = "0.3.0",
    signer_version: str = "0.3.0",
    web_version: str = "0.3.0",
    citation_version: str = "0.3.0",
    citation_date: str | None = None,
    roadmap_heading: str = "## Current candidate: 0.3.0",
    changelog_heading: str = "## [Unreleased]",
) -> None:
    project = root / "agentguard-testbed"
    (project / "signer").mkdir(parents=True)
    (project / "web").mkdir()
    (project / "src" / "aegisledger").mkdir(parents=True)
    (project / "pyproject.toml").write_text(
        f'[project]\nname = "aegisledger"\nversion = "{python_version}"\n',
        encoding="utf-8",
    )
    (project / "signer" / "Cargo.toml").write_text(
        f'[package]\nname = "aegisledger-signer"\nversion = "{signer_version}"\n',
        encoding="utf-8",
    )
    (project / "web" / "package.json").write_text(
        f'{{"name":"@aegisledger/console","version":"{web_version}"}}\n',
        encoding="utf-8",
    )
    (project / "src" / "aegisledger" / "__init__.py").write_text(
        f'__version__ = "{python_version}"\n',
        encoding="utf-8",
    )
    citation = f"version: {citation_version}\n"
    if citation_date is not None:
        citation += f"date-released: {citation_date}\n"
    (root / "CITATION.cff").write_text(citation, encoding="utf-8")
    (root / "CHANGELOG.md").write_text(changelog_heading + "\n", encoding="utf-8")
    (root / "ROADMAP.md").write_text(roadmap_heading + "\n", encoding="utf-8")


def test_candidate_accepts_consistent_unreleased_metadata(tmp_path: Path):
    write_candidate(tmp_path)

    assert collect_versions(tmp_path) == {
        "citation": "0.3.0",
        "python-package": "0.3.0",
        "python-runtime": "0.3.0",
        "rust-signer": "0.3.0",
        "web-console": "0.3.0",
    }
    assert validate_metadata(tmp_path, mode="candidate", tags=()) == []


def test_candidate_rejects_version_drift(tmp_path: Path):
    write_candidate(tmp_path, web_version="0.2.0")

    errors = validate_metadata(tmp_path, mode="candidate", tags=())

    assert any("version mismatch" in error and "web-console=0.2.0" in error for error in errors)


def test_candidate_rejects_a_release_date_or_release_heading(tmp_path: Path):
    write_candidate(
        tmp_path,
        citation_date="2026-07-18",
        changelog_heading="## [0.3.0] - 2026-07-18",
    )

    errors = validate_metadata(tmp_path, mode="candidate", tags=())

    assert "candidate metadata must not set CITATION.cff date-released" in errors
    assert "candidate changelog must retain an [Unreleased] section" in errors


def test_prepared_release_accepts_dated_metadata_before_tagging(tmp_path: Path):
    write_candidate(
        tmp_path,
        citation_date="2026-07-18",
        roadmap_heading="## Current release: 0.3.0",
        changelog_heading="## [0.3.0] - 2026-07-18",
    )

    assert validate_metadata(tmp_path, mode="prepared", tags=()) == []
    assert validate_metadata(tmp_path, mode="auto", tags=()) == []


def test_auto_mode_validates_an_existing_release_tag(tmp_path: Path):
    write_candidate(
        tmp_path,
        citation_date="2026-07-18",
        roadmap_heading="## Current release: 0.3.0",
        changelog_heading="## [0.3.0] - 2026-07-18",
    )

    assert validate_metadata(tmp_path, mode="auto", tags=("v0.3.0",)) == []

    errors = validate_metadata(tmp_path, mode="prepared", tags=("v0.3.0",))
    assert "prepared release already has tag v0.3.0" in errors


def test_release_requires_matching_date_changelog_and_tag(tmp_path: Path):
    write_candidate(
        tmp_path,
        citation_date="2026-07-18",
        roadmap_heading="## Current release: 0.3.0",
        changelog_heading="## [0.3.0] - 2026-07-18",
    )

    assert validate_metadata(tmp_path, mode="release", tags=("v0.3.0",)) == []

    errors = validate_metadata(tmp_path, mode="release", tags=())
    assert "release tag v0.3.0 is missing" in errors


def test_release_rejects_date_or_roadmap_disagreement(tmp_path: Path):
    write_candidate(
        tmp_path,
        citation_date="2026-07-18",
        roadmap_heading="## Current release: 0.2.0",
        changelog_heading="## [0.3.0] - 2026-07-17",
    )

    errors = validate_metadata(tmp_path, mode="release", tags=("v0.3.0",))

    assert "ROADMAP.md must declare Current release: 0.3.0" in errors
    assert "CHANGELOG.md release date must match CITATION.cff date-released" in errors
