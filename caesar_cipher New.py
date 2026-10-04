# DecodeLabs - Cyber Security Project 2
# Basic Encryption & Decryption (Caesar Cipher)
# Name: Ahmad Nawaz
#
# IPO model:
#   Input   -> plaintext from the user + a shift key
#   Process -> shift every letter using ord(), chr() and % 26
#   Output  -> ciphertext, then decrypted text to verify it


def shift_text(text, shift):
    """Shift every English letter in text by 'shift' positions.
    Spaces, digits, punctuation and other symbols stay as they are."""
    result = []

    for char in text:
        if "A" <= char <= "Z":
            # A = 65, so subtract 65, shift, wrap with % 26, add 65 back
            result.append(chr((ord(char) - 65 + shift) % 26 + 65))
        elif "a" <= char <= "z":
            # a = 97
            result.append(chr((ord(char) - 97 + shift) % 26 + 97))
        else:
            result.append(char)

    return "".join(result)


def encrypt(plaintext, key):
    return shift_text(plaintext, key)


def decrypt(ciphertext, key):
    # decryption is just the reverse shift
    return shift_text(ciphertext, -key)


def get_key():
    """Ask for a shift key until a valid whole number is entered."""
    while True:
        value = input("Enter shift key (any whole number, e.g. 3): ").strip()
        try:
            return int(value)
        except ValueError:
            print("Invalid key. Please enter a whole number.\n")


def get_text(prompt):
    """Ask for text and don't accept empty input."""
    while True:
        text = input(prompt)
        if text.strip() != "":
            return text
        print("Text cannot be empty. Try again.\n")


def encrypt_and_verify():
    text = get_text("Enter the text to encrypt: ")
    key = get_key()

    if key % 26 == 0:
        print("\nNote: a key that is a multiple of 26 leaves the text unchanged.")

    encrypted = encrypt(text, key)
    decrypted = decrypt(encrypted, key)

    print("\n--------------------------------")
    print("Original text  :", text)
    print("Shift key      :", key)
    print("Encrypted text :", encrypted)
    print("Decrypted text :", decrypted)

    # decrypting must give back the original message
    if decrypted == text:
        print("Check          : PASSED (decrypted text matches original)")
    else:
        print("Check          : FAILED (something went wrong)")
    print("--------------------------------\n")


def decrypt_only():
    text = get_text("Enter the encrypted text: ")
    key = get_key()

    print("\n--------------------------------")
    print("Encrypted text :", text)
    print("Decrypted text :", decrypt(text, key))
    print("--------------------------------\n")


def brute_force():
    """Try all 25 possible keys (shows why the Caesar cipher is weak)."""
    text = get_text("Enter the encrypted text: ")

    print("\nTrying all possible keys:\n")
    for key in range(1, 26):
        print(f"Key {key:2d} -> {decrypt(text, key)}")
    print()


def main():
    print("=================================")
    print("   CAESAR CIPHER - DecodeLabs")
    print("=================================")

    while True:
        print("1. Encrypt text (and verify by decrypting)")
        print("2. Decrypt text")
        print("3. Brute force (try all keys)")
        print("4. Exit")

        try:
            choice = input("Choose an option (1-4): ").strip()
            print()

            if choice == "1":
                encrypt_and_verify()
            elif choice == "2":
                decrypt_only()
            elif choice == "3":
                brute_force()
            elif choice == "4":
                print("Goodbye!")
                break
            else:
                print("Wrong choice, please enter 1, 2, 3 or 4.\n")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break


if __name__ == "__main__":
    main()
