inp1='1c0111001f010100061a024b53535009181c'
inp2='686974207468652062756c6c277320657965'
expout1 = '746865206b696420646f6e277420706c6179'

s1 = bytes.fromhex(inp1)
s2 = bytes.fromhex(inp2)
out1 = bytearray()
for b1, b2 in zip(s1, s2):
    out1 += (b1 ^ b2).to_bytes()

out1 = out1.hex()

print(out1)
