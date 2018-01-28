import math


def check_length(message, key):
    if len(message) < key:
        raise ValueError("Length of the message is less than the key. Nothing will be encrypted!")

def columnar_encrypt(message, key):
    # If the key is longer than the message nothing happens
    check_length(message, key)

    # Setup a list of empty strings equal to length of key. These are the 'columns' and will get joined together to
    # form the cipher text
    ciphertext = [""] * int(key)

    for column in range(key):
        # Reset the current index to the value of column which will have incremented by one. This 'shifts' the cursor
        # in the message so to speak
        current_index = column

        # Loop through the message using current index to get the nth character and add them to the value for the
        # current index in ciphertext
        while current_index < len(message):
            ciphertext[column] += message[current_index]
            current_index += key

    return "".join(ciphertext)


def columnar_decrypt(message, key):
    # If the key is longer than the message nothing happens
    check_length(message, key)

    # Need to derive the columns by dividing the message and key and rounding up
    column_count = int(math.ceil(len(message) / float(key)))

    # The key determines the number of rows
    row_count = key

    # Number of unused cells to be ignored if needed. They are essentially padding in the last column of the grid
    ignored_cells = (column_count * row_count) - len(message)

    plaintext = [""] * column_count

    # Start the column and row index at 0 then start iterating through the message
    column = 0
    row = 0

    for char in message:
        # As we loop through the message take every nth character and add it to the respective column for that index
        plaintext[column] += char
        # Move the cursor to the next column pointer
        column += 1

        # If we hit the end of the columns loop around. Or, if we're on the last row, see if we need to ignore any cells
        # that are just padding
        if (column == column_count) or (column == column_count -1 and row >= row_count - ignored_cells):
            column = 0
            row += 1

    return "".join(plaintext)

key = 10
cipher_secret = columnar_encrypt("1234567891", key)
print(cipher_secret)
print(columnar_decrypt(cipher_secret, key))
