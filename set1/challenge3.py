inp1='1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

from collections import Counter
import string
import math
import urllib.request
import bs4
from types import MappingProxyType
from typing import Mapping

def decode_message(input_bytes: bytes | memoryview, char: int) -> str | None:
    mess = bytearray()
    for b in input_bytes:
        mess += (b ^ char).to_bytes()
    try:
        mess = mess.decode()
        return mess
    except:
        return None

def test_possible_plaintexts():
    decoded_message = None
    decoded_message_counter = Counter()
    decode_key = None
    inp1b = bytes.fromhex(inp1)

    for c in range(256):
        mess = decode_message(inp1b, c)
        if not mess: continue
        remain = set(mess) - set(string.printable)
        if len(remain) > 0: continue
        mess_cnt = Counter(mess)
        print(repr(mess), 'key', chr(c))
        if mess_cnt['e'] > decoded_message_counter['e']:
            decoded_message_counter = mess_cnt
            decoded_message = mess
            decode_key = chr(c)

    print(decoded_message, 'with key', decode_key)

CHAR_PERCENT_FREQS_ENGLISH = MappingProxyType({
    'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 12.7, 'f': 2.2, 'g': 2.0, 'h': 6.1,
    'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0, 'm': 2.4, 'n': 6.7, 'o': 7.5, 'p': 1.9,
    'q': 0.095, 'r': 6.0, 's': 6.3, 't': 9.1, 'u': 2.8, 'v': 0.98, 'w': 2.4, 'x': 0.15,
    'y': 2.0, 'z': 0.0
})

def fetch_english_freqs() -> MappingProxyType[str, float]:
    return CHAR_PERCENT_FREQS_ENGLISH

def fetch_english_freqs_from_Wikipedia() -> dict[str, float]:
    english_freqs = {}
    URL = 'https://en.wikipedia.org/wiki/Letter_frequency'
    with urllib.request.urlopen(URL) as f:
        soup = bs4.BeautifulSoup(f.read(), features='html.parser')

    table = [table for table in soup.find_all('table') if 'Relative frequency in the English language' in table.get_text()][0]
    rows = table.find_all('tr')[2:]
    for row in rows:
        data = row.find_all('td')
        english_freqs[data[0].get_text().lower().strip()] = float(data[1].get_text().lower().strip().strip('%'))

    return english_freqs

def calculate_score(plaintext: str, english_dist: Mapping[str, float]) -> float:
    '''\
    Assign a score between 0 and 1.
    See https://crypto.stackexchange.com/questions/30209/developing-algorithm-for-detecting-plain-text-via-frequency-analysis
    and https://en.wikipedia.org/wiki/Bhattacharyya_distance#Definition'''

    length = len(plaintext)
    freqs = Counter(plaintext)

    coeff = 0
    for c, p in english_dist.items():
        coeff += math.sqrt((freqs[c]/length) * p)

    return coeff

def break_single_char_xor(ciphertext: bytes | memoryview) -> tuple[str, str]:
    '''Returns tuple of key, plaintext'''
    english_dist = fetch_english_freqs()
    max_score, max_score_message, max_score_key = 0, '', ''
    for c in string.printable:
        message = decode_message(ciphertext, ord(c))
        if not message: continue
        score = calculate_score(message, english_dist)
        if score > max_score:
            max_score_message = message
            max_score_key = c
            max_score = score
    return (max_score_key, max_score_message)

def find_plaintext():
    plaintext, key = break_single_char_xor(bytes.fromhex(inp1))
    print(f'Found {repr(plaintext)} with key {key}')

if __name__ == '__main__':
    find_plaintext()
