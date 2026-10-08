"""The embedded MD5 collision really collides under MD5 and nothing stronger."""

from __future__ import annotations

from securecharge import collision


def test_published_pair_collides_under_md5_only():
    report = collision.analyse()
    assert report.a != report.b  # genuinely different inputs
    assert report.md5_collides  # same MD5
    assert report.same("MD5")
    assert not report.same("SHA-1")
    assert not report.same("SHA-256")
    assert not report.same("SHA3-256")
    assert not report.same("HMAC-SHA3-256")


def test_expected_md5_matches_literature():
    a_md5, b_md5 = collision.analyse().digests["MD5"]
    assert a_md5 == b_md5 == collision.EXPECTED_MD5


def test_common_suffix_preserves_collision():
    assert collision.analyse().suffix_keeps_collision


def test_samples_write_to_disk(tmp_path):
    a, b = collision.write_samples(tmp_path)
    assert a.read_bytes() == collision.COLLISION_A
    assert b.read_bytes() == collision.COLLISION_B
