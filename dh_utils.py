import socket
from random import randint
from hashlib import sha1, sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import urandom
import sys
import struct
from getpass import getpass

nist_p = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919

def send(sock, content):
    # ez casting
    if type(content) not in (bytes, bytearray):
        content = str(content).encode()
    # send packet size first (in 8 bytes)
    sock.sendall(struct.pack('>Q', len(content)))
    # then the actual content
    sock.sendall(content)

def recv(sock):
    # get packet size
    size = struct.unpack('>Q', sock.recv(8))[0]
    return sock.recv(size)

def dh_client(host='localhost', port=9000, p=nist_p, g=2, a=None, data=b"hello"):
    if a is None:
        a = randint(0, p - 1)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        send(sock, p)
        send(sock, g)

        A = pow(g, a, p)
        send(sock, A)
        
        B = int(recv(sock))
        s = pow(B, a, p)
        key = sha1()
        key.update(str(s).encode())
        key = key.digest()[:16]

        iv = urandom(16)
        encrypted = AES.new(key, mode=AES.MODE_CBC, iv=iv).encrypt(pad(data, 16))
        print(encrypted, iv)
        send(sock, encrypted + iv)
        print('Sent:', data)

def dh_server(host='localhost', port=9000):
    print('Starting server...')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, port))
        sock.listen(1)
        conn, _ = sock.accept()

        p = int(recv(conn))
        g = int(recv(conn))
        A = int(recv(conn))

        b = randint(0, p - 1)
        B = pow(g, b, p)

        send(conn, B)

        s = pow(A, b, p)
        key = sha1()
        key.update(str(s).encode())
        key = key.digest()[:16]

        cipher = recv(conn)

        print(cipher)
        decrypted = AES.new(key, mode=AES.MODE_CBC, iv=cipher[-16:]).decrypt(cipher[:-16])
        decrypted = unpad(decrypted, 16)
        print('Received:', decrypted)

    return decrypted

def srp_client(host='localhost', port=9000, username=None, password=None):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))

        # step 1: N=[NIST Prime], g=2, k=3, I (email), P (password)
        N, g, k = nist_p, 2, 3
        # I, P = b'hello@trannn.ml', b'hunter2'
        if username is None:
            I = input('Email: ').encode()
        else:
            I = username.encode()
        if password is None:
            P = getpass().encode()
        else:
            P = password
        
        # step 3
        send(sock, I)
        a = randint(0, N - 1)
        A = pow(g, a, N)
        send(sock, A)

        # step 4
        salt = recv(sock)
        B = int(recv(sock))

        # step 5
        uH = sha256()
        uH.update((str(A) + str(B)).encode())
        u = int(uH.hexdigest(), 16)

        # step 6
        xH = sha256()
        xH.update(salt + P)
        x = int(xH.hexdigest(), 16)
        S = pow(B - k * pow(g, x, N), a + u * x, N)
        K = sha256()
        K.update(str(S).encode())
        K = K.hexdigest().encode()

        # step 8
        hmac = sha256()
        hmac.update(K + salt)
        send(sock, hmac.hexdigest())

        # step 9
        print(recv(sock).decode())

def srp_server(host='localhost', port=9000):
    print('Server started.')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, port))
        sock.listen(1)
        conn, _ = sock.accept()

        # step 1: N=[NIST Prime], g=2, k=3, I (email), P (password)
        N, g, k, I, P = nist_p, 2, 3, b'hello@trannn.ml', b'hunter2'
        
        # step 2
        salt = urandom(8)
        xH = sha256()
        xH.update(salt + P)
        x = int(xH.hexdigest(), 16)
        v = pow(g, x, N)
        del x
        del xH

        # step 3:
        I_recv = recv(conn)
        A = int(recv(conn))

        # step 4
        send(conn, salt)
        b = randint(0, N - 1)
        B = pow(g, b, N)
        B = (B + k * v) % N
        send(conn, B)

        # step 5
        uH = sha256()
        uH.update((str(A) + str(B)).encode())
        u = int(uH.hexdigest(), 16)

        # step 7
        S = pow(A * pow(v, u, N), b, N)
        K = sha256()
        K.update(str(S).encode())
        K = K.hexdigest().encode()

        # step 9
        hmac = sha256()
        hmac.update(K + salt)
        hmac2 = recv(conn)
        # insecure comparison
        auth = (I == I_recv) and (hmac.hexdigest() == hmac2.decode())
        send(conn, 'OK' if auth else 'NG')

if __name__ == "__main__":
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    else:
        port = 9000
    if sys.argv[1] == 'server':
        srp_server('localhost', port)
    elif sys.argv[1] == 'client':
        srp_client('localhost', port)