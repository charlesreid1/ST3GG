"""After the other pipeline tests run, examples/pipelines/ should contain
one artifact per pipeline. This test is a lightweight audit that the
persistence side of each pipeline is wired up.
"""

from __future__ import annotations

import pytest

# Must run last so the other pipeline tests have written their artifacts.
pytestmark = [pytest.mark.pipeline, pytest.mark.regenerates_examples]


EXPECTED_ARTIFACTS = [
    "pipeline_crypto_lsb.png",
    "pipeline_matryoshka.png",
    "pipeline_polyglot.png",
    "pipeline_injector_stack.png",
    "pipeline_multichannel.png",
    "pipeline_covert_text.md",
]


def test_all_pipeline_artifacts_present(pipelines_dir):
    missing = [name for name in EXPECTED_ARTIFACTS
               if not (pipelines_dir / name).exists()]
    # crypto_lsb / covert_text are only produced when cryptography is available.
    import crypto
    if not crypto.HAS_CRYPTO:
        missing = [m for m in missing
                   if m not in ("pipeline_crypto_lsb.png", "pipeline_covert_text.md")]
    assert not missing, f"pipeline artifacts missing: {missing}"


def test_pipeline_artifacts_nonempty(pipelines_dir):
    for name in EXPECTED_ARTIFACTS:
        path = pipelines_dir / name
        if path.exists():
            assert path.stat().st_size > 0, f"{name} is empty"
