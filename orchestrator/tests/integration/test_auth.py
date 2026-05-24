"""
Tests du service auth bcrypt — testent la logique pure (hash/verify) sans DB.
La vérification contre la table api_keys est testée par les tests E2E.
"""
from __future__ import annotations

from orchestrator.services.auth import (
    KEY_PREFIX_TAG, PREFIX_LEN, RANDOM_LEN,
    _generate_key, _hash, _verify,
)


class TestKeyGeneration:
    def test_format(self):
        plaintext, prefix = _generate_key()
        assert plaintext.startswith(KEY_PREFIX_TAG)
        assert len(prefix) == PREFIX_LEN

    def test_unique(self):
        keys = {_generate_key()[0] for _ in range(20)}
        assert len(keys) == 20

    def test_length(self):
        plaintext, _ = _generate_key()
        # mgx_ + PREFIX_LEN + _ + RANDOM_LEN
        assert len(plaintext) >= len(KEY_PREFIX_TAG) + PREFIX_LEN + 1 + RANDOM_LEN


class TestHashAndVerify:
    def test_verify_correct(self):
        plaintext, _ = _generate_key()
        hashed = _hash(plaintext)
        assert _verify(plaintext, hashed) is True

    def test_verify_wrong(self):
        p1, _ = _generate_key()
        p2, _ = _generate_key()
        hashed = _hash(p1)
        assert _verify(p2, hashed) is False

    def test_verify_empty(self):
        hashed = _hash("mgx_abc")
        assert _verify("", hashed) is False

    def test_hash_uses_pepper(self):
        """Deux hash du même plaintext sont différents (salt aléatoire)."""
        p, _ = _generate_key()
        assert _hash(p) != _hash(p)
