import asyncio
import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from contextlib import closing
import pytest
from securecharge import security
from securecharge.blackbox import BlackBox, JournalError, QueueFull, RequestConflict
from securecharge.keys import Keyring
from securecharge.messages import example_start
from securecharge.pilot import fault_experiment


def test_pilot_actual_mutual_tls_outage_lost_reply_and_restart(tmp_path):
    result = asyncio.run(fault_experiment(tmp_path / "public"))
    assert result["outage_retains_pending_without_success_ack"]
    assert result["restart_recovered_authenticated_receipt"]
    assert result["ledger_rows_after_recovery"] == 1
    assert result["tampered_custody_record_rejected_at_startup"]
    assert {p.name for p in (tmp_path / "public").iterdir()} == {"pilot-results.json", "manifest.json"}


def test_queue_conflict_capacity_and_persisted_receipt(tmp_path):
    keys = Keyring.generate()
    box = BlackBox(tmp_path / "queue.sqlite", keys, capacity=1)
    call = example_start()
    identifier = box.enqueue(call, "CP-01")
    assert box.enqueue(call, "CP-01") == identifier
    with pytest.raises(RequestConflict):
        box.enqueue(example_start(meter_start=123), "CP-01")
    with pytest.raises(QueueFull):
        box.enqueue(example_start(unique_id="another"), "CP-01")
    request = security.attach(call, keys, ts=100)
    frame = [3, call.unique_id, {"transactionId": 4, "idTagInfo": {"status": "Accepted"}}]
    reply = security.sign_reply(frame, request, keys, 100)
    bad = copy.deepcopy(reply)
    bad["ocpp"][2]["transactionId"] = 999
    with pytest.raises(security.BadTag):
        box.confirm(identifier, request, bad, 100)
    assert len(box.pending()) == 1
    box.confirm(identifier, request, reply, 100)
    anchor = box.anchor()
    box.close()
    box = BlackBox(tmp_path / "queue.sqlite", keys, capacity=1)
    assert box.response(identifier) == frame and not box.pending()
    assert box.snapshot(anchor)["sequence"] == 2
    box.close()


@pytest.mark.parametrize("change", ["modify", "delete_middle", "reorder"])
def test_storage_tampering_cannot_be_forwarded(tmp_path, change):
    keys = Keyring.generate()
    path = tmp_path / "queue.sqlite"
    box = BlackBox(path, keys)
    box.enqueue(example_start(unique_id="a"), "CP-01")
    box.enqueue(example_start(unique_id="b", connector_id=2), "CP-01")
    box.close()
    with closing(sqlite3.connect(path)) as db:
        if change == "modify":
            db.execute("UPDATE events SET body='{}' WHERE seq=1")
        elif change == "delete_middle":
            db.execute("DELETE FROM events WHERE seq=1")
        else:
            db.execute("UPDATE events SET seq=3 WHERE seq=1")
        db.commit()
    with pytest.raises(JournalError):
        BlackBox(path, keys)


def test_truncation_requires_independent_anchor_and_is_detected(tmp_path):
    keys = Keyring.generate()
    path = tmp_path / "queue.sqlite"
    box = BlackBox(path, keys)
    box.enqueue(example_start(unique_id="a"), "CP-01")
    prefix = box.anchor()
    box.enqueue(example_start(unique_id="b", connector_id=2), "CP-01")
    latest = box.anchor()
    box.close()
    with closing(sqlite3.connect(path)) as db:
        db.execute("DELETE FROM events WHERE seq=2")
        db.commit()
    box = BlackBox(path, keys)
    assert box.snapshot(prefix)["sequence"] == 1  # Explicit limitation: valid suffix deletion alone is invisible.
    with pytest.raises(JournalError, match="truncated"):
        box.snapshot(latest)
    box.close()


def test_actual_abrupt_process_exit_after_queue_commit(tmp_path):
    keys = Keyring.generate()
    # Child exits without closing SQLite or Python cleanup; keys travel in a private test file, not command args.
    config = tmp_path / "test.keys.json"
    config.write_text(
        json.dumps({"active_kid": "gw-1", "keys": {"gw-1": keys.active_key.hex()}, "owners": {"gw-1": "CP-01"}})
    )
    code = """
import os, sys
from pathlib import Path
from securecharge.cli import load_keyring
from securecharge.blackbox import BlackBox
from securecharge.messages import example_start
box = BlackBox(Path(sys.argv[1]) / 'crash.sqlite', load_keyring(Path(sys.argv[1]) / 'test.keys.json'))
box.enqueue(example_start(unique_id='before-crash'), 'CP-01')
os._exit(17)
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path)],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True,
        timeout=20,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert result.returncode == 17, result.stderr.decode()
    box = BlackBox(tmp_path / "crash.sqlite", keys)
    assert box.pending()[0]["call"][1] == "before-crash"
    assert box.db.execute("PRAGMA synchronous").fetchone()[0] == 2
    box.close()


def test_wrong_charger_never_enters_custody(tmp_path):
    box = BlackBox(tmp_path / "queue.sqlite", Keyring.generate())
    with pytest.raises(JournalError, match="not owned"):
        box.enqueue(example_start(), "CP-02")
    assert box.anchor()["sequence"] == 0
    box.close()
