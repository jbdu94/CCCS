"""
The approved baseline for UC4 (Branch A: CI/CD supply chain). This is
"Phase 1: establish the baseline" from the source proposal - captured
once, compared against continuously. Both the benign traffic generator
and the attack script reference these same values (so the attack is a
genuine deviation from a real baseline, not an arbitrary difference),
and the detector imports this same module as its source of truth.
"""

APPROVED_MAINTAINERS = {"jdupont", "msmith", "ci-bot-release"}
APPROVED_RUNNERS = {"runner-prod-01", "runner-prod-02"}
APPROVED_PUBLISHERS = {"ci-bot-release"}

# name@version -> approved sha256. In a real pipeline this comes from a
# signed lockfile/manifest - here it's a static dict for the same reason
# reference_regex_scanner.py in research/ is a static reference: fair,
# reproducible, easy to reason about in a workshop.
LOCKFILE_HASHES = {
    "internal-diagnostics-tool@1.2.0": "a3f8c9e2d1b47650fa9c8e3d2b1a09f8e7d6c5b4a3928170695041322110ffe",
}

# Token scope: which workflow + runner a token is legitimately valid for.
APPROVED_TOKEN_SCOPES = {
    "tok-abc123": {"workflow_id": "wf-release-001", "runner_id": "runner-prod-01"},
}
