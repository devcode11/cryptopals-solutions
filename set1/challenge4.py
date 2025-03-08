from challenge3 import calculate_score, decode_message, fetch_english_freqs

from urllib.request import urlopen
import string
import dataclasses
import pprint

def fetch_input() -> list[bytes]:
    URL = 'https://www.cryptopals.com/static/challenge-data/4.txt'
    with urlopen(URL) as f:
        return f.read().splitlines()

@dataclasses.dataclass
class MaxScore:
    score: float = 0
    ciphertext: str = ''
    plaintext: str = ''
    key: str = ''

def find_plaintext():
    input_strings = fetch_input()
    english_dist = fetch_english_freqs()
    usual_letters = set(string.printable)
    max_score = MaxScore()
    for s in input_strings:
        bs = bytes.fromhex(s.decode())
        for c in string.printable:
            message = decode_message(bs, ord(c))
            if not message: continue
            score = calculate_score(message.lower(), english_dist)
            unusual_letters = set(message) - usual_letters
            if unusual_letters: continue

            if score > max_score.score:
                max_score.score = score
                max_score.plaintext = message
                max_score.ciphertext = bs.decode()
                max_score.key = c

    pprint.pprint(max_score)


if __name__ == '__main__':
    find_plaintext()
