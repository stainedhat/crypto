import pytest

from ciphers.caesar import setup_charset, caesar, crack_caesar

class TestCaesar:
    def test_setup_charset(self):
        # Test default values
        cs, cs_len = setup_charset()
        assert cs == "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]\{}|;\':\",./<>?`~"
        assert cs_len == 94

        # test custom charsets
        charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        cs, cs_len = setup_charset(charset=charset)
        assert cs == charset
        assert isinstance(cs, str)
        assert cs_len == 62

        # Test bad charset
        with pytest.raises(ValueError):
            # this contains duplicates so should raise a ValueError
            charset = "asdfghjklkkjhedbb"
            cs, cs_len = setup_charset(charset)

    def test_caesar(self):
        # Test encryption
        msg = "A super secret message"
        c = caesar(msg, 12, "encrypt")
        assert c == "M 461q3 4qo3q5 yq44msq"

        # Test decryption
        c = caesar("M 461q3 4qo3q5 yq44msq", 12, "decrypt")
        assert c == msg

        # Test custom charset
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        c = caesar(msg, 12, "encrypt", charset=charset)
        assert c == "M EGBqD EqoDqF yqEEmsq"

        c = caesar("M EGBqD EqoDqF yqEEmsq", 12, "decrypt", charset=charset)
        assert c == msg

        # Test bad charset
        with pytest.raises(ValueError):
            # this contains duplicates so should raise a ValueError
            charset = "asdfghjklkkjhedbb"
            c = caesar(msg, 12, "encrypt", charset=charset)

        # Test bad action
        with pytest.raises(ValueError):
            # Action must be either encrypt or decrypt
            c = caesar(msg, 12, "foobar")

        # Test non-integer key raises exception
        with pytest.raises(ValueError):
            c = caesar(msg, "foo", "encrypt")


    def test_crack_caesar(self):
        plaintext = "A super secret message"
        cipherext = "M 461q3 4qo3q5 yq44msq"
        key = 12
        result = crack_caesar(cipherext, charset=None, verbose=False, language="en_US", min_probability=0.75)
        assert result["results"]
        assert result["probable_solutions"][key]["message"] == plaintext
        assert result["probable_solutions"][key]["probability"] == 1.0