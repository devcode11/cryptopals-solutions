input_file_url = 'https://www.cryptopals.com/static/challenge-data/6.txt'

from typing import Callable
from urllib.request import urlopen
import itertools
from challenge3 import break_single_char_xor, calculate_score, fetch_english_freqs
from challenge5 import encrypt_repeating_key_xor
import base64

def hamming_distance(input1: bytes | memoryview, input2: bytes | memoryview) -> int:
    if len(input1) != len(input2):
        raise UserWarning('Length of input1 and input2 are different')
    return sum((b1 ^ b2).bit_count() for b1, b2 in zip(input1, input2))

def test_hamming_dist():
    inp1 = 'this is a test'
    inp2 = 'wokka wokka!!!'
    assert hamming_distance(inp1.encode(), inp2.encode()) == 37

def fetch_input() -> bytes:
    with urlopen(input_file_url) as f:
        return base64.b64decode(f.read())

def block_hamming_distance(block: memoryview, key_size: int, block_count: int) -> float:
    if len(block) < key_size * block_count:
        raise ValueError(f'Block length is less than key size times block count')
    total_dist = 0
    for part1, part2 in itertools.combinations(itertools.batched(block[:key_size * block_count], key_size), 2):
        total_dist += hamming_distance(bytes(part1), bytes(part2)) / key_size
    return total_dist / block_count

def guess_keysize(block: memoryview, block_count: int, key_size_range: range) -> int:
    min_dist = float('inf')
    min_dist_keysize = -1
    mblock = memoryview(block)
    for keysize in key_size_range:
        avg_dist = block_hamming_distance(mblock, keysize, block_count)
        # print(f'{keysize=} {avg_dist=}')
        if avg_dist < min_dist:
            min_dist = avg_dist
            min_dist_keysize = keysize
            # print(f'{min_dist=} {min_dist_keysize=}')
    return min_dist_keysize

def break_repeating_key_xor(block: memoryview, block_count: int, key_size_range: range) -> bytes:
    keysize = guess_keysize(block, block_count, key_size_range)
    # print('Guessed keysize', keysize)
    return break_repeating_key_xor_keysize(block, keysize)

def break_repeating_key_xor_keysize(block: memoryview, keysize: int) -> bytes:
    fullkey = bytearray()
    # print(f'Batches-----------{keysize=}------------')
    # for b in itertools.batched(block, len(block) // keysize): print(b)
    # print('Ciphers-----------------------')
    block_length = len(block)
    slicer: Callable[[int], memoryview] = lambda start: block[start:block_length:keysize]
    for start in range(keysize):
        ciphertext = slicer(start)
        char_key, _ = break_single_char_xor(ciphertext)
        fullkey += char_key.encode()
    return bytes(fullkey)

def solution():
    input_bytes = memoryview(fetch_input())
    # print(input_bytes)
    key = break_repeating_key_xor(input_bytes, block_count=4, key_size_range=range(2, 41))
    message = encrypt_repeating_key_xor(input_bytes, key)

    print(f'''\
{' Decrypted message '.center(40, '=')}
{message.decode()}
{' Key '.center(40, '=')}
{repr(key.decode())}''')

if __name__ == '__main__':
    test_hamming_dist()
    solution()

