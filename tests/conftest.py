import pytest

from ciphers.caesar import DEFAULT_CHARSET


@pytest.fixture(scope="function")
def msg():
    message = {
        "charset": DEFAULT_CHARSET,
        "plaintext": "A super secret message",
        "ciphertext": "M 461q3 4qo3q5 yq44msq",
        "key": 12,
    }

    return message
