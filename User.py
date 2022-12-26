from config import *
from Crypto.Util.number import *
from myCrypto import decodeSHA_StrAsStr

# 用户登陆函数
def user_login(username, password):
    # 从pickle文件中读取用户信息
    user_data = xierluoOpenPickle(User_Pickle_name)
    # 判断用户名和密码是否正确
    if username not in user_data.keys():
        return False, "用户不存在", 0
    elif user_data[username]["password"] == decodeSHA_StrAsStr(xierluoRSA_setMsg(password), 256):
        return username, "登陆成功"
    else:
        return False, "密码错误", 1

def user_reg(username, password):
    user_data = xierluoOpenPickle(User_Pickle_name)
    if username in user_data.keys():
        return False, "用户已存在"
    user_data[username] = {"password": decodeSHA_StrAsStr(xierluoRSA_setMsg(password), 256)}
    xierluoSavePickle(user_data, User_Pickle_name)

    user_seed = xierluoRSA_setMsg(username)
    user_seed = bytes_to_long(base64.b64decode(user_seed))

    seed = user_seed + getPrime(1016)
    us_p = nextprime(seed * 92)
    us_q = nextprime(seed * 77)

    xierluoSavePickle({'name': username, 'seed': user_seed, 'history': 0, 'msg_list': [],
                       'p': us_p, 'q': us_q},
                      Path_Pickle + username + '.pickle')
    return username, "用户成功注册"

def user_get_pickle(username):
    return xierluoOpenPickle(Path_Pickle+username+".pickle")

def user_set_pickle(username, setData):
    setData['history'] += 1
    xierluoSavePickle(setData, Path_Pickle+username+".pickle")
    return

def user_msg_to(username: str, to_msg: str, to_user: str):
    msg = xierluoRSA_setMsg(to_msg, username)
    msg_dict = Msg_Format_dict
    msg_dict['time'] = int(time.time())

    # 发送方
    user_P = user_get_pickle(username)
    msg_dict['user'] = to_user
    msg_dict['format'] = 'to'
    msg_dict['msg'] = ''
    user_P['msg_list'].append(msg_dict)
    user_set_pickle(username, user_P)

    # 接收方
    user_P = user_get_pickle(to_user)
    msg_dict['user'] = username
    msg_dict['format'] = 'from'
    msg_dict['msg'] = msg
    user_P['msg_list'].append(msg_dict)
    user_set_pickle(to_user, user_P)
    return
