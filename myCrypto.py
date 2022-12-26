import re
import gmpy2
import random
import requests
from sympy import *
from hashlib import *
from Crypto.Hash import *
from Crypto.Signature import *
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Util.number import *

class myRsa:
    """
        公钥密码
        公钥: pk = (e,n)
        密钥: sk = (d,n)
        密文: c = m ^e (mod n)
        明文: m = c ^d = m ^(e * d) = m * m ^f_N (mod n) = m
    """
    def __init__(self, p: int, q: int, m: bytes):
        self.p = p
        self.q = q
        self.m = bytes_to_long(m)
        self.e = 65537
        self.c = 0
        self.d = 0
        self.N = 0
        self.f_N = 0
        self.private_key = ""
        self.public_key = ""
        self.init()

    def init(self):
        self.N = self.p * self.q
        self.f_N = (self.p - 1) * (self.q - 1)

        def extendedGCD(fn, b):
            # a*xi + b*yi = ri
            if b == 0:
                return 1, 0, fn
            else:
                x, y, q_ = extendedGCD(b, fn % b)
                x, y = y, (x - (fn // b) * y)
                return x, y, q_

        (x_, d, r) = extendedGCD(self.f_N, self.e)
        # y maybe < 0, so convert it
        if d < 0:
            d += self.f_N
        self.d = d

    def encrypt(self):
        """
        :arg
            self.m: 密文
            self.N: p * q
            self.e: 加密密钥

        :return
            c: 明文
        """
        self.c = pow(self.m, self.e, self.N)
        return long_to_bytes(self.c)

    def decrypt(self):
        """
        :arg
            self.c: 明文
            self.N: p * q
            self.d: 解密密钥

        :return
            m: 密文
        """
        self.m = pow(self.c, self.d, self.N)
        return long_to_bytes(self.m)

    def getD(self):
        self.init()
        return self.encrypt()

    def setM(self, m: bytes):
        self.m = bytes_to_long(m)
        self.init()
        return self.encrypt()

    def setKey(self, p: int, q: int):
        self.q = q
        self.p = p
        self.init()

    def getM(self, c: bytes):
        self.c = bytes_to_long(c)
        self.init()
        return self.decrypt()

    def signature(self):
        self.init()
        key = RSA.construct((self.N, self.e, self.d))
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        self.private_key = RSA.import_key(private_key)
        self.public_key = RSA.import_key(public_key)
        return private_key, public_key

    def Un_sig(self, private_key: bytes, public_key: bytes):
        private_key = RSA.import_key(private_key)
        public_key = RSA.import_key(public_key)
        private_Data = [private_key.p, private_key.q, private_key.e]
        public_Data = [public_key.p, public_key.q, public_key.e]
        for i in range(3):
            tf = private_Data[i] == public_Data[i]
            if not tf:
                return 0, "公私钥不匹配"
        self.private_key = private_key
        self.public_key = public_key
        return 1, "公私钥匹配"


def decodeSHA_StrAsStr(c: str, sha: int):
    c_byte = c.encode()
    if sha == 1:
        m_sha = sha1(c_byte).hexdigest()
    elif sha == 224:
        m_sha = sha224(c_byte).hexdigest()
    elif sha == 256:
        m_sha = sha256(c_byte).hexdigest()
    elif sha == 384:
        m_sha = sha384(c_byte).hexdigest()
    elif sha == 512:
        m_sha = sha512(c_byte).hexdigest()
    else:
        return
    return m_sha


if __name__ == '__main__':
    rsa_now = myRsa(p=getPrime(128), q=getPrime(128), m=b'Hello World!')
    p = rsa_now.p
    print('p:', p)
    q = rsa_now.q
    print('q:', q)
    m = rsa_now.m
    print('m:', m)
    n = p*q
    print(rsa_now.d)
    print(pow(m,65537,n))
    print(rsa_now.signature())

    print(rsa_now.encrypt())
    print(rsa_now.getM(rsa_now.encrypt()))
