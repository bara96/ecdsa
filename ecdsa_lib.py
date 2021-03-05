from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from hashlib import sha256

class ecdsa:
    _public_key = ""
    _signature = ""

    def generateSignature(self, sk=""):
        if sk != "":
            return SigningKey.from_string(sk, curve=SECP256k1, hashfunc=sha256)  # the default is sha1
        else:
            return SigningKey.generate(curve=SECP256k1)


    def signMessage(self, message, signature):
        self._public_key = signature.verifying_key
        self._signature = signature.sign(message)

    def verifyMessage(self, message):
        try:
            self._public_key.verify(self._signature, message)
            print("good signature")
        except BadSignatureError:
            print("BAD SIGNATURE")

    def getPublicKey(self, show=False):
        if show:
            print(self._public_key.to_string())
        return self._public_key

    def setPublicKey(self, pk, from_str=False):
        if from_str:
            self._public_key = VerifyingKey.from_string(pk, curve=SECP256k1, hashfunc=sha256)  # the default is sha1
        else:
            self._public_key = pk

    def getSignature(self, show=False):
        if show:
            print(self._signature)
        return self._signature

    def setSignature(self, sign, from_str=False):
        if from_str:
            self._signature = SigningKey.from_string(sign, curve=SECP256k1, hashfunc=sha256)  # the default is sha1
        else:
            self._signature = sign