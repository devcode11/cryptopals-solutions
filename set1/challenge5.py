inp1='''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
inp_key = 'ICE'
expected_output = '''0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'''

import itertools

def encrypt_repeating_key_xor(plaintext: bytes | memoryview, key: bytes) -> bytes:
    out = bytearray()
    for c, k in zip(plaintext, itertools.cycle(key)):
        out += (c ^ k).to_bytes()
    return bytes(out)

def solution():
    input_bytes = inp1.encode()
    key_bytes = inp_key.encode()
    ciphertext = encrypt_repeating_key_xor(input_bytes, key_bytes)
    assert ciphertext.hex() == expected_output
    print(ciphertext.hex())

if __name__ == '__main__':
    solution()


