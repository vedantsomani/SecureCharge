import sqlite3
from concurrent.futures import ThreadPoolExecutor
from securecharge.storage import Store
from securecharge.backend import SecureCsms
from securecharge.clock import FakeClock
from securecharge.keys import Keyring
from securecharge.messages import example_start
from securecharge import security


def test_nonces_are_scoped_per_key():
    s = Store()
    assert s.claim_nonce(nonce="a" * 32, key_id="gw-1", msg_ts=100, now=100)
    assert s.claim_nonce(nonce="a" * 32, key_id="gw-2", msg_ts=100, now=100)
    assert not s.claim_nonce(nonce="a" * 32, key_id="gw-1", msg_ts=100, now=100)


def test_v1_database_migration_preserves_nonces(tmp_path):
    path = tmp_path / "old.sqlite"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE seen_nonces(nonce TEXT PRIMARY KEY,key_id TEXT NOT NULL,msg_ts INTEGER NOT NULL,seen_at INTEGER NOT NULL)"
    )
    conn.execute("INSERT INTO seen_nonces VALUES ('n','old-key',100,100)")
    conn.commit()
    conn.close()
    s = Store(path)
    assert s.nonce_count() == 1
    assert not s.claim_nonce(nonce="n", key_id="old-key", msg_ts=100, now=100)
    assert s.claim_nonce(nonce="n", key_id="new-key", msg_ts=100, now=100)


def test_replay_atomic_across_independent_sqlite_connections(tmp_path):
    path = tmp_path / "shared.sqlite"
    stores = [Store(path), Store(path)]
    k = Keyring.generate()
    clock = FakeClock(100)
    backends = [SecureCsms(k, s, clock=clock) for s in stores]
    frame = security.attach(example_start(), k, ts=100).to_frame()
    with ThreadPoolExecutor(max_workers=2) as pool:
        verdicts = list(pool.map(lambda b: b.receive(frame), backends))
    assert sum(v.accepted for v in verdicts) == 1
    assert stores[0].nonce_count() == 1
