"""Tests for protocol module."""

import pytest
from fxtunnel.protocol import (
    MsgType,
    generate_key, key_to_hex, hex_to_key,
    Cipher,
    build_open_port_msg, parse_open_port_msg,
    build_port_opened_msg, parse_port_opened_msg,
    build_new_conn_msg, parse_new_conn_msg,
    generate_challenge, compute_auth_response, verify_auth_response,
    CHALLENGE_SIZE
)


class TestKeyGeneration:
    """Tests for key generation and conversion."""

    def test_generate_key_length(self):
        """Generated key should be 32 bytes (256 bits)."""
        key = generate_key()
        assert len(key) == 32

    def test_generate_key_uniqueness(self):
        """Each generated key should be unique."""
        keys = [generate_key() for _ in range(10)]
        unique_keys = set(keys)
        assert len(unique_keys) == 10

    def test_key_to_hex(self):
        """Key should convert to 64-character hex string."""
        key = generate_key()
        hex_str = key_to_hex(key)
        assert len(hex_str) == 64
        assert all(c in '0123456789abcdef' for c in hex_str)

    def test_hex_to_key(self):
        """Hex string should convert back to key."""
        key = generate_key()
        hex_str = key_to_hex(key)
        recovered = hex_to_key(hex_str)
        assert key == recovered

    def test_key_roundtrip(self):
        """Key conversion should be reversible."""
        original = generate_key()
        hex_str = key_to_hex(original)
        recovered = hex_to_key(hex_str)
        assert original == recovered


class TestCipher:
    """Tests for AES-256-GCM cipher."""

    def test_encrypt_decrypt(self):
        """Encrypted data should decrypt to original."""
        key = generate_key()
        cipher = Cipher(key)

        plaintext = b"Hello, World!"
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_encrypt_produces_different_output(self):
        """Same plaintext should produce different ciphertext (due to nonce)."""
        key = generate_key()
        cipher = Cipher(key)

        plaintext = b"Test message"
        ciphertext1 = cipher.encrypt(plaintext)
        ciphertext2 = cipher.encrypt(plaintext)

        assert ciphertext1 != ciphertext2

    def test_ciphertext_longer_than_plaintext(self):
        """Ciphertext includes nonce (12 bytes) and auth tag (16 bytes)."""
        key = generate_key()
        cipher = Cipher(key)

        plaintext = b"Test"
        ciphertext = cipher.encrypt(plaintext)

        # Nonce (12) + plaintext (4) + auth tag (16) = 32
        assert len(ciphertext) == len(plaintext) + 12 + 16

    def test_decrypt_with_wrong_key_fails(self):
        """Decryption with wrong key should fail."""
        key1 = generate_key()
        key2 = generate_key()
        cipher1 = Cipher(key1)
        cipher2 = Cipher(key2)

        plaintext = b"Secret message"
        ciphertext = cipher1.encrypt(plaintext)

        with pytest.raises(Exception):
            cipher2.decrypt(ciphertext)

    def test_empty_message(self):
        """Empty message should encrypt and decrypt correctly."""
        key = generate_key()
        cipher = Cipher(key)

        plaintext = b""
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_large_message(self):
        """Large messages should encrypt and decrypt correctly."""
        key = generate_key()
        cipher = Cipher(key)

        plaintext = b"x" * 100000  # 100 KB
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        assert decrypted == plaintext


class TestMessageBuilders:
    """Tests for message builder and parser functions."""

    def test_open_port_msg(self):
        """OPEN_PORT message should encode and decode correctly."""
        port = 5432
        mode = "tcp"

        data = build_open_port_msg(port, mode)
        parsed_port, parsed_mode = parse_open_port_msg(data)

        assert parsed_port == port
        assert parsed_mode == mode

    def test_open_port_msg_udp(self):
        """OPEN_PORT with UDP mode should work."""
        port = 53
        mode = "udp"

        data = build_open_port_msg(port, mode)
        parsed_port, parsed_mode = parse_open_port_msg(data)

        assert parsed_port == port
        assert parsed_mode == mode

    def test_port_opened_msg(self):
        """PORT_OPENED message should encode and decode correctly."""
        port = 8080

        data = build_port_opened_msg(port)
        parsed_port = parse_port_opened_msg(data)

        assert parsed_port == port

    def test_new_conn_msg_tcp(self):
        """NEW_CONN message for TCP should work."""
        port = 3000

        data = build_new_conn_msg(port, is_udp=False)
        parsed_port, is_udp = parse_new_conn_msg(data)

        assert parsed_port == port
        assert is_udp is False

    def test_new_conn_msg_udp(self):
        """NEW_CONN message for UDP should work."""
        port = 53

        data = build_new_conn_msg(port, is_udp=True)
        parsed_port, is_udp = parse_new_conn_msg(data)

        assert parsed_port == port
        assert is_udp is True

    def test_new_conn_msg_legacy_format(self):
        """Legacy NEW_CONN format (2 bytes) should parse as TCP."""
        import struct
        port = 5432

        # Legacy format: just 2 bytes for port
        data = struct.pack("!H", port)
        parsed_port, is_udp = parse_new_conn_msg(data)

        assert parsed_port == port
        assert is_udp is False


class TestAuthentication:
    """Tests for challenge-response authentication."""

    def test_generate_challenge_length(self):
        """Challenge should be 32 bytes."""
        challenge = generate_challenge()
        assert len(challenge) == CHALLENGE_SIZE

    def test_generate_challenge_uniqueness(self):
        """Each challenge should be unique."""
        challenges = [generate_challenge() for _ in range(10)]
        unique = set(challenges)
        assert len(unique) == 10

    def test_compute_auth_response_deterministic(self):
        """Same key and challenge should produce same response."""
        key = generate_key()
        challenge = generate_challenge()

        response1 = compute_auth_response(key, challenge)
        response2 = compute_auth_response(key, challenge)

        assert response1 == response2

    def test_verify_auth_response_valid(self):
        """Valid response should verify successfully."""
        key = generate_key()
        challenge = generate_challenge()
        response = compute_auth_response(key, challenge)

        assert verify_auth_response(key, challenge, response) is True

    def test_verify_auth_response_wrong_key(self):
        """Response with wrong key should fail verification."""
        key1 = generate_key()
        key2 = generate_key()
        challenge = generate_challenge()
        response = compute_auth_response(key1, challenge)

        assert verify_auth_response(key2, challenge, response) is False

    def test_verify_auth_response_wrong_challenge(self):
        """Response for different challenge should fail verification."""
        key = generate_key()
        challenge1 = generate_challenge()
        challenge2 = generate_challenge()
        response = compute_auth_response(key, challenge1)

        assert verify_auth_response(key, challenge2, response) is False

    def test_verify_auth_response_tampered(self):
        """Tampered response should fail verification."""
        key = generate_key()
        challenge = generate_challenge()
        response = compute_auth_response(key, challenge)

        # Tamper with response
        tampered = bytes([response[0] ^ 1]) + response[1:]

        assert verify_auth_response(key, challenge, tampered) is False


class TestMsgType:
    """Tests for message type enum."""

    def test_message_types_exist(self):
        """All expected message types should exist."""
        assert MsgType.SERVER_IDENTITY == 0
        assert MsgType.AUTH == 1
        assert MsgType.AUTH_CHALLENGE == 2
        assert MsgType.AUTH_RESPONSE == 3
        assert MsgType.AUTH_OK == 4
        assert MsgType.AUTH_FAIL == 5
        assert MsgType.NEW_CONN == 20
        assert MsgType.DATA == 30
        assert MsgType.PING == 40
        assert MsgType.PONG == 41
        assert MsgType.SHUTDOWN == 50
