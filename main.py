from typing import List
from des_tables import IP, FP, E, P, PC1, PC2, SHIFTS, S_BOXES

def bytes_to_bits(b: bytes) -> List[int]:
    return [int(bit) for byte in b for bit in format(byte, '08b')]

def bits_to_bytes(bits: List[int]) -> bytes:
    assert len(bits) % 8 == 0
    out = bytearray()

    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        out.append(int(''.join(str(x) for x in byte), 2))

    return bytes(out)

def permute(bits: List[int], table: List[int]) -> List[int]:
    return [bits[i-1] for i in table]

def left_rotate(lst: List[int], n: int) -> List[int]:
    n = n % len(lst)
    return lst[n:] + lst[:n]

def xor_bits(a: List[int], b: List[int]) -> List[int]:
    return [x ^ y for x,y in zip(a,b)]

def generate_subkeys(key_64bits: bytes) -> List[List[int]]:
    if len(key_64bits) != 8:
        raise ValueError("Chave deve ser 8 bytes (64 bits).")
    
    key_bits = bytes_to_bits(key_64bits)
    key56 = permute(key_bits, PC1)
    C = key56[:28]
    D = key56[28:]
    subkeys = []

    for shift in SHIFTS:
        C = left_rotate(C, shift)
        D = left_rotate(D, shift)
        CD = C + D
        subkey = permute(CD, PC2)
        subkeys.append(subkey)

    return subkeys

def feistel(R: List[int], subkey48: List[int]) -> List[int]:
    ER = permute(R, E)
    xored = xor_bits(ER, subkey48)
    out_bits = []

    for i in range(8):
        block6 = xored[i*6:(i+1)*6]
        row = (block6[0] << 1) | block6[5]
        col = (block6[1] << 3) | (block6[2] << 2) | (block6[3] << 1) | block6[4]
        s_val = S_BOXES[i][row][col]
        out_bits.extend([int(b) for b in format(s_val, '04b')])

    return permute(out_bits, P)

def des_block(block64bits: bytes, subkeys: List[List[int]], decrypt: bool=False) -> bytes:
    if len(block64bits) != 8:
        raise ValueError("Bloco deve ter 8 bytes.")
    
    bits = bytes_to_bits(block64bits)
    permuted = permute(bits, IP)
    L = permuted[:32]
    R = permuted[32:]

    if decrypt:
        round_keys = subkeys[::-1]
    else:
        round_keys = subkeys
    for k in round_keys:
        f_out = feistel(R, k)
        newL = R
        newR = xor_bits(L, f_out)
        L, R = newL, newR

    preoutput = R + L
    final_bits = permute(preoutput, FP)
    return bits_to_bytes(final_bits)

def pkcs7_pad(data: bytes, block_size: int=8) -> bytes:
    pad_len = block_size - (len(data) % block_size)

    if pad_len == 0:
        pad_len = block_size

    return data + bytes([pad_len])*pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    if len(data) == 0:
        raise ValueError("Dados vazios ao desempacotar.")
    
    pad_len = data[-1]

    if pad_len < 1 or pad_len > 8:
        raise ValueError("Padding inválido.")
    if data[-pad_len:] != bytes([pad_len])*pad_len:
        raise ValueError("Padding inválido.")
    
    return data[:-pad_len]

def des_encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != 8:
        raise ValueError("Chave deve ter 8 bytes.")
    
    padded = pkcs7_pad(plaintext, 8)
    subkeys = generate_subkeys(key)
    cipher = bytearray()

    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        cipher_block = des_block(block, subkeys, decrypt=False)
        cipher.extend(cipher_block)

    return bytes(cipher)

def des_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != 8:
        raise ValueError("Chave deve ter 8 bytes.")
    
    if len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext length must be multiple of 8.")
    
    subkeys = generate_subkeys(key)
    out = bytearray()

    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        plain_block = des_block(block, subkeys, decrypt=True)
        out.extend(plain_block)
        
    return pkcs7_unpad(bytes(out))

if __name__ == "__main__":
    key = input("Digite a chave de criptografia (exatamente 8 caracteres): ").encode("utf-8")

    if len(key) != 8:
        raise ValueError("❌ Erro: a chave deve conter exatamente 8 caracteres.")
    
    msg = input("Digite a mensagem a ser cifrada: ").encode("utf-8")

    cipher = des_encrypt(msg, key)
    print("Cifrado:", cipher.hex())

    recovered = des_decrypt(cipher, key)
    print("Decifrado:", recovered.decode("utf-8", errors="ignore"))
