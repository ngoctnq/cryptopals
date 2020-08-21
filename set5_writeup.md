<sup>Đây là một bài trong series [Cùng giải Cryptopals!](https://viblo.asia/s/cung-giai-cryptopals-68Z00nw9ZkG).<br>Các bạn nên tự làm hoặc vừa đọc vừa làm thay vì đọc lời giải trực tiếp.</sup>
***
**<div align="center">Không chần chừ gì nữa, hãy bắt đầu nào!</div>**
***

# [Challenge 33: Implement Diffie-Hellman](https://cryptopals.com/sets/5/challenges/33)

Bài này chỉ việc implement theo đúng những gì được hướng dẫn:
```python
p = ...
g = 2

a = randint(0, p - 1)
A = pow(g, a, p)

b = randint(0, p - 1)
B = pow(g, b, p)

s = pow(B, a, p)
assert s == pow(A, b, p)
```

# [Challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection](https://cryptopals.com/sets/5/challenges/34)

Đầu tiên, chúng ta implement hàm nhận và gửi để nhận đúng kích cỡ từng tin nhắn: trước khi gửi/nhận, socket sẽ gửi/nhận một tin nhắn 8 byte cho biết kích cỡ thật của tin nhắn là gì.
```python
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
```

Chúng ta implement A dưới dạng client (người gửi tin nhắn). Nhớ cung cấp các param cần thiết theo signature.
```python
def client_send(host='localhost', port=9000, p=nist_p, g=2, a=None, data=b"hello"):
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

        iv = os.urandom(16)
        encrypted = AES.new(key, mode=AES.MODE_CBC, iv=iv).encrypt(pad(data, 16))
        send(sock, encrypted + iv)
        print('Sent:', data)
```

Và code của server (người nhận B):
```python
def start_server(host='localhost', port=9000):
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
        decrypted = AES.new(key, mode=AES.MODE_CBC, iv=cipher[-16:]).decrypt(cipher[:-16])
        print('Received:', unpad(decrypted, 16))
```

Nếu public key là $p$ thì common key sẽ là $p^a\mod p = 0$ với mọi private key $a$. Từ đó, AES key sẽ là $\text{SHA1}(0)[0:16]$. Code của MITM như sau:
```python
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
```

# [Challenge 35: Implement DH with negotiated groups, and break with malicious "g" parameters](https://cryptopals.com/sets/5/challenges/35)

- Nếu $g=1$, tất cả các private key sẽ đều là 1, và shared secret $s$ là 1.
- Nếu $g=p$, tất cả các private key sẽ đều là 0, và shared secret $s$ là 0.
- Nếu $g=p-1$, public key sẽ là $\pm1$ phụ thuộc vào tính chẵn lẻ của private key. Nếu chúng ta chốt private key của MITM là một số chẵn (ví dụ, 2), thì shared secret $s$ sẽ là 1.

# [Challenge 36: Implement Secure Remote Password (SRP)](https://cryptopals.com/sets/5/challenges/36)

Vẫn chỉ là bài tập về lập trình.

Code client:
```python
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
```

Code server:
```python
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
```

Như đề bài đã nói thì về cơ bản đây là Diffie-Hellman có trộn thêm thông tin về password vào trong common key. <sup>[1]</sup> Trong đó, $u$ và $k$ có ý nghĩa tương tự nhau: trọng số này ở đây để tránh việc trộn 2 phần thông tin (key exchange $g^b$ / password verification $g^x$) bằng nhau:

$$
B = kv + g^b = k\times g^x + g^b.
$$

Với shared secret $S$, sau một hồi tính toán:

$$
S = g^{a\times b} \times g^{x\times u\times b}.
$$

Hãy để ý rằng, hàm ở dưới phải mũ $u$ thay vì nhân, vì phép gốc là phép nhân. Nếu chúng ta lấy $\log_g$ sẽ thấy một công thức có mối quan hệ tuyến tính tương tự:

$$
\log_gS=a\times b + u\times x\times b,
$$

với trọng số $u$ sẽ "hoà" thông tin về password vào cùng với thông tin DH authentication trong shared secret.

<sup>[1]</sup> Tất cả các công thức toán đều được tính ở modulo $N$ cho đơn giản.

# [Challenge 37: Break SRP with a zero key](https://cryptopals.com/sets/5/challenges/37)

Với $A=0$ (hay bất cứ bội số nào của $N$), chúng ta sẽ có $S=A^b\times g^{x\times u\times b}=0$ không phụ thuộc vào $x$ (password).


# [Challenge 38: Offline dictionary attack on simplified SRP](https://cryptopals.com/sets/5/challenges/38)

Do $B$ không phụ thuộc vào password, shared secret có thể tính được từ phía client mà không cần proof-of-knowledge từ phía server. Ngược lại, với SRP, nếu server (hay MITM attacker) mà không biết password, shared secret được sinh ra bên client sẽ không thể tính được bên server, bởi từ bên client số bị mũ sẽ là

$$
B - kg^{x'} = g^b + k(g^x-g^{x'}),
$$

và sau khi mũ thì tổng này sau khi phá ra sẽ tùm lum. Đồng thời, trong số mũ có $a$, và 2 tỉ các term lẻ làm cho phương trình không thể bị tối giản sao cho không còn phụ thuộc vào $a$ để bên server bruteforce được. Nếu muốn phá shared secret đó thì attacker cũng phải phá được $a$, và điều đó trái ngược với giả thiết bài toán khó log modulo.

Do vậy, mà chỉ phiên bản SRP đơn giản hoá mới offline dictionary/bruteforce được.


# [Challenge 39: Implement RSA](https://cryptopals.com/sets/5/challenges/39)

Viết code cho Extended Euclidean Algorithm:
```python
def egcd(m: int, n: int) -> (int, (int, int)):
    # return gcd(m, n) = mx + ny in this order: (gcd(m, n), (x, y))
    assert m > 0 and n > 0, "Parameters to `egcd` must be positive."
    m_coeff = (1, 0)
    n_coeff = (0, 1)
    if m < n:
        m, n = n, m
        m_coeff, n_coeff = n_coeff, m_coeff

    while True:
        r, q = divmod(m, n)
        if q == 0:
            return n, n_coeff
        m, n = n, q
        # q = m - n * r
        m_coeff, n_coeff = n_coeff, tuple(map(lambda x: x[0] - r * x[1], zip(m_coeff, n_coeff)))
```

Và code cho modular inverse:
```python
def invmod(n: int, p: int) -> int:
    # return the modular inverse under Zp
    g, (x, _) = egcd(n, p)
    assert g == 1, 'Can only invmod on mutually prime numbers.'
    return x % p
```

Và phần RSA thì rất đơn giản:
```python
p = 47 # chua qua
q = 53 # da toi
n = p * q
phi = (p - 1) * (q - 1)
e = 3
d = invmod(e, phi)

# encrypt & decrypt
s = 42
encrypted = pow(s, e, n)
decrypted = pow(encrypted, d, n)
assert decrypted == s
```

# [Challenge 40: Implement an E=3 RSA Broadcast attack](https://cryptopals.com/sets/5/challenges/40)

Về cơ bản đây là Håstad's broadcast attack — chúng ta cần $e$ phiên bản encryption của cùng một tin nhắn để có thể recover được tin nhắn đó. Đương nhiên là làm theo hướng dẫn sẽ auto được rồi:
```python
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
```

Ngoại trừ việc nó không cứ auto là được, do exponent $e$ bé dễ gây bị chia hết cho Euler's totient, nên không inverse được để lấy private exponent.

***
**<div align="center">Hết rồi đó.</div>**
***