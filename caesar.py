import enchant


def setup_charset(charset=None):
    """
    Common functionality between the caesar functions so better to abstract it out
    :param charset: a string containing the desired charset or None to get default charset. Cannot contain duplicates!
    :return: A charset and it's given length
    """
    if not charset:
        charset = str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]\{}|;\':\",./<>?`~")
    else:
        charset = str(charset)

    duplicates = set()
    for c in charset:
        if c in duplicates:
            raise ValueError("The charset cannot contain duplicates")
        else:
            duplicates.add(c)

    charset_len = len(charset)

    return charset, charset_len


def caesar(message, key, action="encrypt", charset=None):
    """
    Perform either encryption or decryption using the Caesar Cipher.
    :param message: String message t0 encrypt or decrypt
    :param key: An integer to be used as the encryption or decryption key
    :param action: Must be either encrypt or decrypt
    :param charset: Any string to be used as a charset. Cannot contain duplicates!
    :return: The encrypted or decrypted string
    """
    charset, charset_len = setup_charset(charset)

    # Ensure good starting types or raise an error during casting
    key = int(key)
    message = str(message)

    result = ""

    for char in message:
        if char in charset:
            char_index = charset.find(char)

            if action == "encrypt":
                new_index = char_index + key
            elif action == "decrypt":
                new_index = char_index - key
            else:
                raise ValueError("The action argument must be either encrypt or decrypt")

            if new_index >= charset_len:
                new_index -= charset_len
            elif new_index < 0:
                new_index += charset_len

            result += charset[new_index]
        else:
            result += char

    return result


def crack_caesar(message, charset=None, verbose=False, language="en_US", min_probability=0.75):
    """
    Brute force all keys in the charset and look for a plaintext message
    :param message: Encrypted Caesar cipher message
    :param charset: The charset used to encrypt the message
    :param verbose: Boolean to print out the results or not
    :param language: The default language set to use for checking if something is a word
    :param min_probability: Minimum probability threshold for possible matches. max is 1 and higher is more accurate
    :return: dict() containing all results and possible solutions. Solutions dicts contain the probability the key is
    accurate and the decrypted message for that key
    """
    charset, charset_len = setup_charset(charset)

    message = str(message)
    dictionary = enchant.Dict(language)

    results = {}
    probable_solutions = {}

    # Iterate through all of the indexes in the given charset and try to decrypt the message using each index as the key
    for key in range(charset_len):
        decrypted = ""

        for char in message:
            if char in charset:
                char_index = charset.find(char)
                new_index = char_index - key

                if new_index < 0:
                    new_index += charset_len

                decrypted += charset[new_index]
            else:
                decrypted += char

        results[key] = decrypted

        # Check if the majority of the words are english. If so, this is probably the key we're looking for
        decrypted_parts = decrypted.split(" ")
        num_words = len(decrypted_parts)
        probability  = 0
        for word in decrypted_parts:
            if dictionary.check(word):
                # This is a valid english word according to enchants dictionary
                probability += 1
        probability = round(float(probability) / num_words, 2)
        if probability > min_probability:
            # More than 75% of the words are english so this could possibly be our secret
            probable_solutions[key] = {
                "probability": probability,
                "message": decrypted
            }


    if verbose:
        for k, v in results.items():
            print("Key: {0: >2} \tMessage: {1}".format(k,  v))

    findings = {
        "results": results,
        "probable_solutions": probable_solutions
    }

    return findings


# Encrypt a message then crack it
msg = caesar("A super secret message", 12, "encrypt")
print(msg)
cracked = crack_caesar(msg)
print(cracked["probable_solutions"])