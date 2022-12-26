from User import *
from config import *

def test():
    P = user_get_pickle('Xierluo')['msg_list']
    P2 = user_get_pickle('admin')['msg_list']
    print(P)
    print(P2)


def base_config():
    print("基础设置")
    username, password = 'admin', 'flag{this_is_RSA_plus}'
    xierluoSavePickle(config_rsa(), DataRSA_pickle_name)
    xierluoSavePickle({username: {"password": decodeSHA_StrAsStr(xierluoRSA_setMsg(password), 256)}},
                      User_Pickle_name)

    user_seed = xierluoRSA_setMsg(username)
    user_seed = bytes_to_long(base64.b64decode(user_seed))

    seed = user_seed + getPrime(1016)
    us_p = nextprime(seed * 92)
    us_q = nextprime(seed * 77)

    xierluoSavePickle({'name': username, 'seed': user_seed, 'history': 0, 'msg_list': [],
                       'p': us_p, 'q': us_q},
                      Path_Pickle + username + '.pickle')


if __name__ == '__main__':
    test()
