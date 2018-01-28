import pytest

from ciphers.caesar import setup_charset, caesar, crack_caesar
from ciphers.caesar import DEFAULT_CHARSET, DEFAULT_LANGUAGE, DEFAULT_MIN_PROBABILITY


"""
Fixtures:
msg - dict() containing the following:
message = {
        "charset": DEFAULT_CHARSET,
        "plaintext": "A super secret message",
        "caesar_ciphertext": "M 461q3 4qo3q5 yq44msq",
        "key": 12,
    }
"""

class TestCaesar:
    ##### setup_charsets() #####
    def test_setup_charset_default_charsets(self):
        # Test default values
        cs, cs_len = setup_charset()
        assert cs == DEFAULT_CHARSET
        assert cs_len == len(DEFAULT_CHARSET)

    def test_setup_charset_custom_charsets(self):
        # test custom charsets
        charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        cs, cs_len = setup_charset(charset=charset)
        assert cs == charset
        assert isinstance(cs, str)
        assert cs_len == 62

    def test_setup_charset_exceptions_bad_charset(self):
        # Test bad charset
        with pytest.raises(ValueError):
            # this contains duplicates so should raise a ValueError
            charset = "asdfghjklkkjhedbb"
            cs, cs_len = setup_charset(charset)


    ##### caesar() #####
    def test_caesar_encryption(self, msg):
        # Test encryption
        c = caesar(msg["plaintext"], msg["key"], "encrypt")
        assert c == msg["caesar_ciphertext"]

    def test_caesar_decryption(self, msg):
        # Test decryption
        c = caesar(msg["caesar_ciphertext"], msg["key"], "decrypt")
        assert c == msg["plaintext"]

    def test_caesar_custom_charsets(self, msg):
        # Test custom charsets
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        plaintext = msg["plaintext"]
        ciphertext = "M EGBqD EqoDqF yqEEmsq"
        # Test encrypt
        c = caesar(plaintext, msg["key"], "encrypt", charset=charset)
        assert c == ciphertext
        # Test decrypt
        c = caesar(ciphertext, msg["key"], "decrypt", charset=charset)
        assert c == plaintext

    def test_caesar_exceptions_duplicates_in_charset(self, msg):
        # Test bad charset
        with pytest.raises(ValueError):
            # this contains duplicates so should raise a ValueError
            charset = "asdfghjklkkjhedbb"
            caesar(msg["plaintext"], msg["key"], "encrypt", charset=charset)

    def test_caesar_exceptions_bad_action(self, msg):
        # Test bad action
        with pytest.raises(ValueError):
            # Action must be either encrypt or decrypt
            caesar(msg["plaintext"], msg["key"], "foobar")

    def test_caesar_exceptions_non_integer_key(self, msg):
        # Test non-integer key raises exception
        with pytest.raises(ValueError):
            caesar(msg["plaintext"], "foo", "encrypt")


    ##### crack_caesar() #####
    def test_crack_caesar_results(self, msg):
        plaintext = msg["plaintext"]
        ciphertext = msg["caesar_ciphertext"]
        key = msg["key"]
        result = crack_caesar(ciphertext, charset=None, verbose=False,
                              language=DEFAULT_LANGUAGE, min_probability=DEFAULT_MIN_PROBABILITY)
        assert result["results"]

    def test_crack_caesar_probable_solutions(self, msg):
        plaintext = msg["plaintext"]
        ciphertext = msg["caesar_ciphertext"]
        key = msg["key"]
        result = crack_caesar(ciphertext, charset=None, verbose=False,
                              language=DEFAULT_LANGUAGE, min_probability=DEFAULT_MIN_PROBABILITY)
        assert result["probable_solutions"][key]["message"] == plaintext
        assert result["probable_solutions"][key]["probability"] == 1.0
