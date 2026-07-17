#!/usr/bin/env python3
"""Deploy the smart account to Anvil and prove direct-RPC enforcement."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OWNER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ATTACKER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    executable = shutil.which(args[0])
    if executable is None:
        raise RuntimeError(f"required executable is unavailable: {args[0]}")
    return subprocess.run(  # noqa: S603 - commands and arguments are locally constructed
        (executable, *args[1:]),
        cwd=ROOT,
        check=check,
        text=True,
        capture_output=True,
    )


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def deploy(contract: str, rpc_url: str, *constructor_args: str) -> str:
    command = [
        "forge",
        "create",
        contract,
        "--rpc-url",
        rpc_url,
        "--private-key",
        OWNER_KEY,
        "--broadcast",
        "--json",
    ]
    if constructor_args:
        command.extend(["--constructor-args", *constructor_args])
    result = run(*command)
    payload = json.loads(result.stdout)
    return payload["deployedTo"]


def main() -> int:
    port = free_port()
    rpc_url = f"http://127.0.0.1:{port}"
    anvil_executable = shutil.which("anvil")
    if anvil_executable is None:
        raise RuntimeError("Anvil is required for the integration test")
    anvil = subprocess.Popen(  # noqa: S603 - fixed local integration-test command
        [anvil_executable, "--silent", "--port", str(port), "--chain-id", "31337"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        for _ in range(50):
            ready = run("cast", "chain-id", "--rpc-url", rpc_url, check=False)
            if ready.returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Anvil did not become ready")

        owner = run("cast", "wallet", "address", "--private-key", OWNER_KEY).stdout.strip()
        attacker = run("cast", "wallet", "address", "--private-key", ATTACKER_KEY).stdout.strip()
        recipient = "0x000000000000000000000000000000000000bEEF"
        account = deploy(
            "contracts/src/AegisSmartAccount.sol:AegisSmartAccount",
            rpc_url,
            owner,
            "1000",
            "5000",
        )
        token = deploy("contracts/test/AegisSmartAccount.t.sol:MockToken", rpc_url)

        def send(
            target: str,
            signature: str,
            *values: str,
            key: str = OWNER_KEY,
            check: bool = True,
        ):
            return run(
                "cast",
                "send",
                target,
                signature,
                *values,
                "--rpc-url",
                rpc_url,
                "--private-key",
                key,
                check=check,
            )

        send(token, "mint(address,uint256)", account, "10000")
        send(account, "setAsset(address,bool)", token, "true")
        send(account, "setTarget(address,bool)", token, "true")
        send(account, "setRecipient(address,bool)", recipient, "true")
        send(account, "setSelector(address,bytes4,bool)", token, "0xa9059cbb", "true")

        transfer_data = run(
            "cast", "calldata", "transfer(address,uint256)", recipient, "100"
        ).stdout.strip()
        deadline = str(int(time.time()) + 600)
        execution = f"(1,{token},0,{transfer_data},{token},100,{recipient},0,{deadline})"
        tuple_type = "(uint8,address,uint256,bytes,address,uint256,address,uint256,uint256)"
        digest = run(
            "cast",
            "call",
            account,
            f"executionDigest({tuple_type})(bytes32)",
            execution,
            "--rpc-url",
            rpc_url,
        ).stdout.strip()
        attacker_signature = run(
            "cast", "wallet", "sign", "--no-hash", digest, "--private-key", ATTACKER_KEY
        ).stdout.strip()
        bypass = send(
            account,
            f"execute({tuple_type},bytes)(bytes)",
            execution,
            attacker_signature,
            key=ATTACKER_KEY,
            check=False,
        )
        if bypass.returncode == 0:
            raise AssertionError("attacker-signed direct RPC execution unexpectedly succeeded")

        owner_signature = run(
            "cast", "wallet", "sign", "--no-hash", digest, "--private-key", OWNER_KEY
        ).stdout.strip()
        send(
            account,
            f"execute({tuple_type},bytes)(bytes)",
            execution,
            owner_signature,
            key=ATTACKER_KEY,
        )
        balance = run(
            "cast",
            "call",
            token,
            "balanceOf(address)(uint256)",
            recipient,
            "--rpc-url",
            rpc_url,
        ).stdout.strip()
        if int(balance) != 100:
            raise AssertionError(f"unexpected recipient balance: {balance}")
        print(
            json.dumps(
                {
                    "chain_id": 31337,
                    "account": account,
                    "attacker": attacker,
                    "direct_bypass_rejected": True,
                    "authorized_relay_settled": True,
                },
                sort_keys=True,
            )
        )
        return 0
    finally:
        anvil.terminate()
        try:
            anvil.wait(timeout=5)
        except subprocess.TimeoutExpired:
            anvil.kill()
            anvil.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
