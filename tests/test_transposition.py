import pytest

from ciphers.transposition import check_length, columnar_decrypt, columnar_encrypt

class TestTransposition:
    ##### columnar_encrypt() #####
    def test_columnar_encrypt(self, msg):
        cipher_secret = columnar_encrypt(msg["plaintext"], msg["key"])
        assert cipher_secret == msg["columnar_ciphertext"]


    ##### columnar_decrypt() #####
    def test_columnar_decrypt(self, msg):
        cipher_secret = columnar_decrypt(msg["columnar_ciphertext"], msg["key"])
        assert cipher_secret == msg["plaintext"]