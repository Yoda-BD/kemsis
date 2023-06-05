from random import sample
from itertools import product as col
import math
from PIL import Image
import os

# Caesar Cipher
def encrypt_Caesar(text, s):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr((ord(char) + s - 65) % 26 + 65)
        else:
            result += chr((ord(char) + s - 97) % 26 + 97)
    return result

def vigenere_encrypt(plaintext, key):
    encrypted_text = ""
    key_length = len(key)
    for i in range(len(plaintext)):
        char = plaintext[i]
        if char.isalpha():
            key_char = key[i % key_length]
            key_index = ord(key_char.upper()) - 65
            if char.islower():
                encrypted_char = chr((ord(char) - 97 + key_index) % 26 + 97)
            else:
                encrypted_char = chr((ord(char) - 65 + key_index) % 26 + 65)
            encrypted_text += encrypted_char
        else:
            encrypted_text += char
    return encrypted_text

def decrypt_Caesar(text, s):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr((ord(char) - s - 65) % 26 + 65)
        else:
            result += chr((ord(char) - s - 97) % 26 + 97)
    return result

def vigenere_decrypt(ciphertext, key):
    decrypted_text = ""
    key_length = len(key)
    for i in range(len(ciphertext)):
        char = ciphertext[i]
        if char.isalpha():
            key_char = key[i % key_length]
            key_index = ord(key_char.upper()) - 65
            if char.islower():
                decrypted_char = chr((ord(char) - 97 - key_index) % 26 + 97)
            else:
                decrypted_char = chr((ord(char) - 65 - key_index) % 26 + 65)
            decrypted_text += decrypted_char
        else:
            decrypted_text += char
    return decrypted_text


def hide_secret_message(text, vigenere_key, stego_path):
    key_byte = bytearray(vigenere_key, "utf-8")
    key_binary = []
    for x in key_byte:
        key_binary.append(format(x, "08b"))
    key_binary = "".join(key_binary)

    secret_byte = bytearray(text, "utf-8")
    secret_binary = []
    for x in secret_byte:
        secret_binary.append(format(x, "08b"))
    secret_binary = "".join(secret_binary)

    combined_binary = key_binary + secret_binary

    stego_size = math.ceil(math.sqrt(len(combined_binary)))

    cover = Image.new("RGB", (stego_size, stego_size))

    cursor = 0
    for y in range(cover.size[1]):
        for x in range(cover.size[0]):
            pixel = (0, 0, 0)  

            if cursor < len(combined_binary):
                bit = int(combined_binary[cursor])
                pixel_value = bit * 255 
                pixel = (pixel_value, pixel_value, pixel_value)
                cursor += 1

            cover.putpixel((x, y), pixel)

    stego_dir = os.path.dirname(stego_path)
    stego_name = os.path.basename(stego_path)
    stego_name_without_ext = os.path.splitext(stego_name)[0]
    stego_save_path = os.path.join(stego_dir, stego_name_without_ext + "_encrypted.png")
    cover.save(stego_save_path)

    print("Encrypted message and Vigenere key have been hidden in the image.")
    print("Encrypted image is saved at: " + stego_save_path)


def extract_secret_message(stego_path):
    stego = Image.open(stego_path)
    secret = ""
    for y in range(stego.size[1]):
        for x in range(stego.size[0]):
            pixel = stego.getpixel((x, y))
            secret = secret + str(pixel[1] % 2)

    secret_ascii = ""
    for x in range(0, len(secret), 8):
        tmp = secret[x:x + 8]
        tmp = int(tmp, 2)
        secret_ascii = secret_ascii + chr(tmp)
    return secret_ascii\

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    mode = input("Select mode: [1] Encryption or [2] Decryption: ")

    if mode == '1':
        kalimat = input("Enter the sentence: ")
        kata = kalimat.split()
        cipher_text = ""  # Variable to store the cipher text from both techniques
        caesar_key = ""  # Variable to store the Caesar Cipher key
        vigenere_key = ""  # Variable to store the Vigenere Cipher key

        for i, k in enumerate(kata):
            if i % 2 == 0:
                text = k
                s = 3
                enkripsi_caesar = encrypt_Caesar(text, s)
                cipher_text += enkripsi_caesar + " "  # Add Caesar Cipher cipher text to the cipher_text variable
                caesar_key += str(s) + " "  # Add Caesar Cipher key to the caesar_key variable
            elif i % 2 == 1:
                x = k
                key = "SECRET"
                enkripsi_vigenere = vigenere_encrypt(x, key)
                cipher_text += enkripsi_vigenere + " "  # Add Vigenere Cipher cipher text to the cipher_text variable
                vigenere_key += key + " "  # Add Vigenere Cipher key to the vigenere_key variable

        print("Cipher Text: " + cipher_text)
        print("Caesar Key: " + caesar_key)
        print("Vigenere Key: " + vigenere_key)

        # Hide encrypted message in an image
        cover_path = input("Enter the cover image path: ")
        hide_secret_message(cipher_text, vigenere_key, cover_path)
        input("Press Enter to Back")
        clear()
        main()


    elif mode == '2':
        # Extract encrypted message from a stego image
        stego_path = input("Enter the stego image path: ").strip()
        # stego_path = input("Enter the stego image path: ")
        secret_message = extract_secret_message(stego_path)
        print("Hidden Message: " + secret_message)

        plain_text = ""  # Variable to store the plain text from both techniques
        caesar_key = ""  # Variable to store the Caesar Cipher key
        vigenere_key = ""  # Variable to store the Vigenere Cipher key

        kalimat = input("Enter the sentence: ")
        kata = kalimat.split()

        for i, k in enumerate(kata):
            if i % 2 == 0:
                text = k
                s = int(input("Enter the Caesar Cipher key for decryption: "))
                dekripsi_caesar = decrypt_Caesar(text, s)
                plain_text += dekripsi_caesar + " "  # Add Caesar Cipher plain text to the plain_text variable
                caesar_key += str(s) + " "  # Add Caesar Cipher key to the caesar_key variable
            elif i % 2 == 1:
                x = k
                key = input("Enter the Vigenere Cipher key for decryption: ")
                dekripsi_vigenere = vigenere_decrypt(x, key)
                plain_text += dekripsi_vigenere + " "  # Add Vigenere Cipher plain text to the plain_text variable
                vigenere_key += key + " "  # Add Vigenere Cipher key to the vigenere_key variable

        print("Plain Text: " + plain_text)
        print("Caesar Key: " + caesar_key)
        print("Vigenere Key: " + vigenere_key)
        input("Press Enter to Back")
        clear()
        main()

    else:
        print("Invalid mode selection.")
        input("Press Enter to Back")
        clear()
        main()

if __name__ == "__main__":
    main()
