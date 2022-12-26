import time
import json
import base64
import pickle
import random
from sympy import *
from myCrypto import myRsa
from myCrypto import decodeSHA_StrAsStr

from Crypto.Util.number import *

Path_Pickle = "static/pickle/"
User_Pickle_name = "static/pickle/user_data.pickle"
DataRSA_pickle_name = "static/pickle/RSA_data.pickle"

No_redi_list = ['login', 'register', 'js', 'css']
Msg_Format_dict = {'format': '', 'msg': '', 'user': '', 'time': 0}


def xierluoOpenPickle(pickleName):
    return pickle.load(open(pickleName, "rb"))

def xierluoSavePickle(data, pickleName):
    file_ = open(pickleName, "wb")
    pickle.dump(data, file_)
    file_.close()

def xierluoRSA(user: str = None):
    if not user:
        rsa_base = xierluoOpenPickle(DataRSA_pickle_name)
    else:
        rsa_base = xierluoOpenPickle(Path_Pickle + user + '.pickle')
    now_rsa = myRsa(q=rsa_base['q'], p=rsa_base['p'], m=b"\x00")
    return now_rsa

def xierluoRSA_setMsg(data: str, user: str = None) -> str:
    if not user:
        now_rsa = xierluoRSA()
    else:
        now_rsa = xierluoRSA(user)
    now_msg = now_rsa.setM(data.encode())
    return base64.b64encode(now_msg).decode()

def xierluoRSA_getMsg(base64_data: str, user: str = None) -> str:
    if not user:
        now_rsa = xierluoRSA()
    else:
        now_rsa = xierluoRSA(user)
    data = base64.b64decode(base64_data)
    return now_rsa.getM(data).decode()

def config_rsa():
    seed = getPrime(1024)
    bits = seed.bit_length()
    while True:
        p = getPrime(bits + 1)
        if p > seed:
            break
    a = getRandomRange(1, p)
    b = getRandomRange(1, p)
    rsa_data_ = {'q': seed, 'p': p}

    for _ in range(3):
        seed = (a * seed + b) % p
        rsa_data_['seed' + str(_)] = seed
    return rsa_data_


if __name__ == '__main__':
    print("基础设置")
    xierluoSavePickle(config_rsa(), DataRSA_pickle_name)
    xierluoSavePickle({'admin':
                           {"password": decodeSHA_StrAsStr(xierluoRSA_setMsg("flag{this_is_RSA_plus}"), 256)}
                       },
                      User_Pickle_name)
    # print(decodeSHA_StrAsStr(xierluoRSA_setMsg("flag{this_is_RSA_plus}"), 256))
