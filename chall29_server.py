from time import sleep
from flask import Flask, request
from sha1 import sha1

def insecure_compare(h1: str, h2: str) -> bool:
    if len(h1) != len(h2): return False
    for c1, c2 in zip(h1, h2):
        if c1 != c2:
            return False
        sleep(0.005)
    return True

app = Flask(__name__)
@app.route('/test')
def check_hash():
    f = request.args.get('file')
    h = request.args.get('signature')
    if f is None or h is None:
        return 'bad', 400
    real = sha1(f.encode())
    if insecure_compare(h, real):
        return 'ok', 200
    else:
        return 'ng', 500

if __name__ == '__main__':
    app.run(port=9000, debug=True)