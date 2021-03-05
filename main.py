from ecdsa_lib import ecdsa

public_key = b"\xa0\xe0\xb6\x1f'\xc3U\x8a\x06\x1a<\x1f\xb2\xc2\xfc@\xce\xa9\xd7ih\xb6L\xa4\xa3\xc5\xb0\xfb\xa6\x96\x0c\xe6\x1e\xbf\xa5o\x03\xaf\x11v\xf9\xbd<&\\?\x8f\xd9\xc1!jLR\xbf\xcb\xb1Q\x1b\xa3\xb0\xf5`\xaa\x81"
sig = b'#\xba\x11<[x\xb8\xd4\x11\xe0\xf1\x08Q\xb4W\x01\xabI@q\x83?\x8f\xab\xdc\xe9X\xb7\xee@RI'

message = b"message"
ecdsa = ecdsa()
sk = ecdsa.generateSignature()
ecdsa.signMessage(message, sk)
#ecdsa.setPublicKey(public_key, True)
ecdsa.verifyMessage(message)