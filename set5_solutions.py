from utils import * #pylint:disable=unused-wildcard-import
from dh_utils import send, recv, socket, sha1, unpad, sha256, nist_p

def chall33():
    # diffie-hellman
    p = int('''
        ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
        fffffffffffff
        '''.replace(' ', '').replace('\n', ''), 16)
    g = 2

    a = randint(0, p - 1)
    A = pow(g, a, p)

    b = randint(0, p - 1)
    B = pow(g, b, p)

    s = pow(B, a, p)
    assert s == pow(A, b, p)

def chall34(port_in=9000, port_out=9001):
    # sender
    sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sender.bind(('localhost', port_out))
    sender.listen(1)
    conn, _ = sender.accept()

    # receiver
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', port_in))

    # step 1
    p = int(recv(conn))
    g = int(recv(conn))
    recv(conn)

    # step 2
    send(sock, p)
    send(sock, g)
    send(sock, p)

    # step 3
    recv(sock)

    # step 4
    send(conn, p)

    # step 5
    cipher = recv(conn)

    print(cipher)

    # step 6
    send(sock, cipher)

    # decrypting as the MITM
    key = sha1()
    key.update(b'0')
    key = key.digest()[:16]
    decrypted = AES.new(key, mode=AES.MODE_CBC, iv=cipher[-16:]).decrypt(cipher[:-16])
    decrypted = unpad(decrypted, 16)
    print('Received:', decrypted)

def chall36():
    def srp_client(host='localhost', port=9000, A=None):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))

            # step 1: N=[NIST Prime], g=2, k=3, I (email), P (password)
            N, g, k = nist_p, 2, 3
            # I, P = b'hello@trannn.ml', b'hunter2'
            I, P = b'hello@trannn.ml', b''
            
            # step 3
            send(sock, I)
            a = randint(0, N - 1)
            if A is None:
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
            if A % N == 0:
                S = 0
            else:
                S = pow(B - k * pow(g, x, N), a + u * x, N)
            K = sha256()
            K.update(str(S).encode())
            K = K.hexdigest().encode()

            # step 8
            hmac = sha256()
            hmac.update(K + salt)
            send(sock, hmac.hexdigest())

            # step 9
            res = recv(sock).decode()
            print(res)
            return res == 'OK'
    # srp_client()
    srp_client(A=0)
    # srp_client(A=nist_p)
    # srp_client(A=nist_p * 2)

def chall39():
    from rsa import invmod, getPrime
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 3
    d = invmod(e, phi)

    # encrypt & decrypt
    s = 42
    encrypted = pow(s, e, n)
    decrypted = pow(encrypted, d, n)
    assert decrypted == s

def chall40():
    from rsa import invmod, getPrime
    p1 = getPrime(1024)
    p2 = getPrime(1024)
    p3 = getPrime(1024)
    q1 = getPrime(1024)
    q2 = getPrime(1024)
    q3 = getPrime(1024)

    n1 = p1 * q1
    n2 = p2 * q2
    n3 = p3 * q3
    e = 3

    # encrypt & decrypt
    s = 42
    e1 = pow(s, e, n1)
    e2 = pow(s, e, n2)
    e3 = pow(s, e, n3)

    result = (
        e1 * n2 * n3 * invmod(n2 * n3, n1) +
        e2 * n1 * n3 * invmod(n1 * n3, n2) +
        e3 * n1 * n2 * invmod(n1 * n2, n3)
    ) % (n1 * n2 * n3)
    decrypted = round(result ** (1/3))
    assert decrypted == s
