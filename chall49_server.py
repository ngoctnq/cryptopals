from flask import Flask, request
from utils import generate_key, AES_encrypt, pkcs7_pad
import re

app = Flask(__name__)
key = generate_key(16)

@app.route('/sign', methods=['POST'])
def sign():
    # some sick authorization here
    if False: return ('NG', 403)
    try:
        data = request.json
        msg = f"from={data['acc_from']}&to={data['acc_to']}&amount={data['amount']}".encode()
    except:
        return 'NG', 400
    iv = generate_key()
    mac = AES_encrypt(key, pkcs7_pad(msg), 'cbc', iv)[-16:]
    return msg + iv + mac

@app.route('/send', methods=['POST'])
def send_monii():
    data = request.data
    if len(data) <= 32: return 'NG', 400
    mac = data[-16:]
    iv = data[-32:-16]
    msg = data[:-32]
    if AES_encrypt(key, pkcs7_pad(msg), 'cbc', iv)[-16:] != mac:
        return 'NG', 400
    try:
        # the three vals returned are acc_from, acc_to, and amount
        re.match(r'^from=(\d+)&to=(\d+)&amount=(\d+)$', msg.decode()).groups()
    except:
        return 'NG', 400
    return 'OK', 200

@app.route('/sign2', methods=['POST'])
def sign2():
    # some sick authorization here
    if False: return ('NG', 403)
    try:
        data = request.json
        msg = f"from={data['acc_from']}&txlist=" + \
              ';'.join([f'{x[0]}:{x[1]}' for x in data['txlist'].items()])
        msg = msg.encode()
    except:
        return 'NG', 400
    mac = AES_encrypt(key, pkcs7_pad(msg), 'cbc')[-16:]
    return msg + mac

@app.route('/send2', methods=['POST'])
def send2():
    data = request.data
    if len(data) <= 16: return 'NG', 400
    mac = data[-16:]
    msg = data[:-16]
    if AES_encrypt(key, pkcs7_pad(msg), 'cbc')[-16:] != mac:
        return 'NG', 400
    try:
        # learn regex, it's fun
        # re.match(r'^from=(\d+)&txlist=(\d+):(\d+)(?:;(\d+):(\d+))*$', msg.decode()).groups()
        re.match(rb'^from=(\d+)&txlist=([^:;]+):([^:;]+)(?:;([^:;]+):([^:;]+))*$', msg).groups()
    except:
        return 'NG', 400
    return 'OK', 200

if __name__ == '__main__':
    app.run(port=9000, debug=True)