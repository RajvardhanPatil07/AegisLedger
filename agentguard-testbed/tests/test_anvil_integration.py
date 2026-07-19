import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.anvil
@pytest.mark.skipif(os.getenv("RUN_ANVIL_TESTS") != "1", reason="set RUN_ANVIL_TESTS=1")
def test_deployed_smart_account_rejects_direct_rpc_bypass():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "scripts/run_anvil_integration.py"],
        cwd=root,
        check=True,
        text=True,
        capture_output=True,
    )
    assert '"direct_bypass_rejected": true' in result.stdout
    assert '"authorized_relay_settled": true' in result.stdout
