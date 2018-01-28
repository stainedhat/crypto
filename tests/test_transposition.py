import pytest
import random

from ciphers.transposition import check_length, columnar_decrypt, columnar_encrypt, columnar_brute_force


"""
Pytest Fixtures:
msg - dict() containing the following:
message = {
        "charset": DEFAULT_CHARSET,
        "plaintext": "A super secret message",
        "caesar_ciphertext": "M 461q3 4qo3q5 yq44msq",
        "columnar_ciphertext": "Ae ts umpeesrs asgeecr",
        "key": 12,
    }
"""

class TestTransposition:
    ##### check_length() #####
    def test_check_length(self):
        message = "Too short!"
        key = len(message) + 1
        with pytest.raises(ValueError):
            check_length(message, key)


    ##### columnar_encrypt() #####
    def test_columnar_encrypt(self, msg):
        cipher_secret = columnar_encrypt(msg["plaintext"], msg["key"])
        assert cipher_secret == msg["columnar_ciphertext"]


    ##### columnar_decrypt() #####
    def test_columnar_decrypt(self, msg):
        cipher_secret = columnar_decrypt(msg["columnar_ciphertext"], msg["key"])
        assert cipher_secret == msg["plaintext"]


    ##### columnar_brute_force() #####
    def test_columnar_brute_force_results(self, msg):
        results = columnar_brute_force(msg["columnar_ciphertext"])
        assert results


    def test_columnar_brute_force_results_length(self, msg):
        results = columnar_brute_force(msg["columnar_ciphertext"])
        assert len(results) == 1

    def test_columnar_brute_force_result_key(self, msg):
        results = columnar_brute_force(msg["columnar_ciphertext"])
        # Length should only be one result for this test. Validated by test above
        for key in results:
            assert key ==  msg["key"]

    def test_columnar_brute_force_result_message(self, msg):
        results = columnar_brute_force(msg["columnar_ciphertext"])
        assert results[msg["key"]]["message"] ==  msg["plaintext"]

    def test_columnar_brute_force_result_probability(self, msg):
        results = columnar_brute_force(msg["columnar_ciphertext"])
        assert results[msg["key"]]["probability"] ==  1.0

    def test_columnar_brute_force_random_values(self, msg):
        # Encrypt using 5 random key values and ensure they are each properly decrypted and identified
        for i in range(5):
            key = random.randint(2, 10)
            encrypted = columnar_encrypt(msg["plaintext"], key)
            results = columnar_brute_force(encrypted)
            assert results[key]["message"] == msg["plaintext"]