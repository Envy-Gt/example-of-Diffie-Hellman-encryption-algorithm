def mod_exp(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent // 2
        base = (base * base) % modulus
    return result

def diffie_hellman(p, g, private_a, private_b):
    # Calculate public keys
    public_a = mod_exp(g, private_a, p)
    public_b = mod_exp(g, private_b, p)

    # Exchange public keys
    shared_key_a = mod_exp(public_b, private_a, p)
    shared_key_b = mod_exp(public_a, private_b, p)

    return shared_key_a, shared_key_b

def encrypt(message, key):
    encrypted_message = []
    for char in message:
        encrypted_char = chr(ord(char) + key)
        encrypted_message.append(encrypted_char)
    return ''.join(encrypted_message)

def decrypt(encrypted_message, key):
    decrypted_message = []
    for char in encrypted_message:
        decrypted_char = chr(ord(char) - key)
        decrypted_message.append(decrypted_char)
    return ''.join(decrypted_message)

# Example usage:
if __name__ == "__main__":
    # Common parameters (usually agreed upon by communicating parties)
    p = 23  # Prime number
    g = 5   # Generator

    # Private keys for Alice and Bob
    private_key_alice = 6
    private_key_bob = 15

    # Perform Diffie-Hellman key exchange
    shared_key_alice, shared_key_bob = diffie_hellman(p, g, private_key_alice, private_key_bob)

    # Encrypt a message using the shared key
    secret_message = "Hello, secret message!"
    encrypted_message = encrypt(secret_message, shared_key_alice)

    print("Original Message:", secret_message)

    # Decrypt the message using the shared key
    decrypted_message = decrypt(encrypted_message, shared_key_bob)
    print("Decrypted Message:", decrypted_message)



