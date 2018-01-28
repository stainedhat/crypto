import enchant

DEFAULT_MIN_PROBABILITY = 0.75
DEFAULT_LANGUAGE = "en_US"

dictionary = enchant.Dict(DEFAULT_LANGUAGE)

def word_check(message):
    # Define and remove all symbols so enchant spell check works properly
    symbols = ["`", "~", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "+", "=", "{", "}", "[", "]", "|",
               "\\", ":", ";", "\"", "'", "<", ">", ",", ".", "?", "/"]
    for symbol in symbols:
        if symbol in message:
            message.replace(symbol, "")

    message_parts = message.split(" ")
    num_words = len(message_parts)
    probability = 0

    for word in message.split(" "):
        # Seems more pythonic than catching an exception from enchant when looking up a blank value
        if word:
            if dictionary.check(word):
                # This is a valid english word according to enchants dictionary
                probability += 1

    probability = round(float(probability) / num_words, 2)
    return probability