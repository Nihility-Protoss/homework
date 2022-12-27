from flask import Flask
from flask import request
from flask import render_template
from flask import make_response
from flask import Response
from flask import redirect
from flask import session
from flask import url_for

from User import *
from myCrypto import *

# 创建flask应用
app = Flask(__name__, template_folder='static')
app.config['SECRET_KEY'] = 'XXXXXX'
app.debug = True

# 访问前置路由，识别登陆状态
@app.before_request
def check_login():
    user_id = session.get('userID')
    if '/' in request.path:
        to_path = request.path.split('/')[1]
    else:
        to_path = ''

    if not user_id and to_path not in No_redi_list:
        return redirect('/login')

# 主界面
@app.route('/index', methods=['GET', 'POST'])
def index():
    userID = session['userID']
    ret_msg = session['ret_msg']
    user_P = user_get_pickle(userID)
    user_list = xierluoOpenPickle(User_Pickle_name).keys()

    if request.method == 'POST':
        to_user = request.form.get('to_user')
        to_msg = request.form.get('to_msg')
        if to_user in user_list:
            user_msg_to(userID, to_msg, to_user)
            ret_msg = "消息发送完毕"
        else:
            ret_msg = "没有找到目标用户"
        session['ret_msg'] = ret_msg
        return redirect('/index')

    if user_P['msg_list']:
        msg_list = [i['user'] for i in user_P['msg_list']]
    else:
        msg_list = []
    if ret_msg:
        session['ret_msg'] = ""

    msg_rt_dict = {}
    for i in msg_list:
        if i not in msg_rt_dict.keys():
            msg_rt_dict[i] = 0
        msg_rt_dict[i] += 1
    return render_template('html/index.html', msg_dict=msg_rt_dict.items(), msg_list=msg_list,
                           ret_msg=ret_msg, **{'msg': str(userID)})

# 登陆模块
@app.route('/login', methods=['GET', 'POST'])
def user_login_page():
    # 如果是post请求，则调用user_login函数
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        check = user_login(username, password)
        if check[0]:
            session['userID'] = check[0]
            session['ret_msg'] = ''
            return redirect('/index')
        else:
            return render_template('html/login.html', **{'msg': check[1]})
    # 如果是get请求，则返回登陆页面
    else:
        return render_template('html/login.html')

# 注册模块
@app.route('/register', methods=['GET', 'POST'])
def user_reg_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        check = request.form.get('sig')
        if check != 'XXXX123123123':
            return render_template('html/register.html')
        check = user_reg(username, password)
        if check[0]:
            session['userID'] = check[0]
            session['ret_msg'] = ''
            return redirect('/index')
        else:
            return render_template('html/register.html', **{'msg': check[1]})
    else:
        return render_template('html/register.html')

# 查看信息页面
@app.route('/msg/<string:name>', methods=['GET', 'POST'])
def msg_socket(name):
    userID = session['userID']
    otherID = name
    if request.method == 'POST':
        to_msg = request.form.get('to_msg')
        user_msg_to(userID, to_msg, otherID)
        return redirect('/msg/'+otherID)

    msg_list = []
    user_P = user_get_pickle(userID)
    otherP = user_get_pickle(otherID)
    for i in user_P['msg_list']:
        if i['format'] == 'from' and i['user'] == otherID:
            msg_list.append(i)
    for i in otherP['msg_list']:
        if i['format'] == 'from' and i['user'] == userID:
            msg_list.append(i)

    msg_list.sort(key=lambda k: (k.get('time', 0)))
    msg_list = [[i['user'] == userID, xierluoRSA_getMsg(i['msg'], i['user'])] for i in msg_list]

    return render_template('html/msg.html', msg_list=msg_list, **{'name1': userID, 'name2': otherID})

# rsa加解密页面
@app.route('/rsa', methods=['GET', 'POST'])
def rsa_page():
    userID = session['userID']
    ret_msg = session['ret_msg']
    user_P = user_get_pickle(userID)
    type_now = request.args.get('type', 'encrypt', type=str)
    if 'us_p' not in user_P.keys() and 'us_q' not in user_P.keys():
        now_rsa = myRsa(p=user_P['p'], q=user_P['q'], m=b'\x00')
    else:
        now_rsa = myRsa(p=user_P['us_p'], q=user_P['us_q'], m=b'\x00')

    if request.method == 'POST':
        data = request.form.get('need_rsa')
        # 如果是加密，则调用rsa_encrypt函数
        if type_now == 'encrypt':
            now_msg = now_rsa.setM(data.encode())
            session['ret_msg'] = base64.b64encode(now_msg).decode()
        # 如果是解密，则调用rsa_decrypt函数
        elif type_now == 'decrypt':
            data = base64.b64decode(data)
            session['ret_msg'] = now_rsa.getM(data).decode()
        return redirect('/rsa?type='+type_now)

    if ret_msg:
        session['ret_msg'] = ""

    return render_template('html/rsa.html', rsa_data=ret_msg)

# 获取用户RSA加密
@app.route('/rsa/getUserRSA', methods=['POST'])
def rsa_getUserRSA():
    userID = session['userID']
    user_P = user_get_pickle(userID)

    if 'us_p' not in user_P.keys() and 'us_q' not in user_P.keys():
        now_rsa = myRsa(p=user_P['p'], q=user_P['q'], m=b'\x00')
    else:
        now_rsa = myRsa(p=user_P['us_p'], q=user_P['us_q'], m=b'\x00')

    private_key, public_key = now_rsa.signature()
    rt_dict = {"private_key": private_key, 'public_key': public_key, "tf": True, "msg": "生成完毕"}

    next_json = json.dumps(rt_dict, separators=(',', ':'), ensure_ascii=False)
    return next_json

# 用户自填RSA密钥
@app.route("/rsa/setUserRSA", methods=['POST'])
def rsa_setUserRSA():
    userID = session['userID']
    user_P = user_get_pickle(userID)

    us_private_sig = request.form.get('us_private')
    us_public_sig = request.form.get('us_public')
    try:
        us_private = RSA.import_key(us_private_sig)
        us_public = RSA.import_key(us_public_sig)
    except ValueError as e:
        return json.dumps({"tf": False, "msg": "输入数据异常"}, separators=(',', ':'), ensure_ascii=False)
    if us_public.e != 65537:
        return json.dumps({"tf": False, "msg": "E值应为65537！"}, separators=(',', ':'), ensure_ascii=False)

    us_p = us_private.p
    us_q = us_private.q
    now_rsa = myRsa(p=us_p, q=us_q, m=b'\x00')
    tf, msg = now_rsa.Un_sig(private_key=us_private_sig, public_key=us_private_sig)
    if not tf:
        return json.dumps({"tf": False, "msg": msg}, separators=(',', ':'), ensure_ascii=False)

    user_P['us_p'] = us_p
    user_P['us_q'] = us_q
    user_set_pickle(userID, user_P)
    rt_dict = {"private_key": us_private_sig, 'public_key': us_private_sig, "tf": True, "msg": "使用用户定义PQ值成功"}

    next_json = json.dumps(rt_dict, separators=(',', ':'), ensure_ascii=False)
    return next_json


if __name__ == '__main__':
    app.run()
