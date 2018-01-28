import pytest

from ciphers.caesar import DEFAULT_CHARSET


@pytest.fixture(scope="session")
def msg():
    message = {
        "charset": DEFAULT_CHARSET,
        "plaintext": "A super secret message",
        "caesar_ciphertext": "M 461q3 4qo3q5 yq44msq",
        "columnar_ciphertext": "Ae ts umpeesrs asgeecr",
        "key": 12,
    }

    return message
