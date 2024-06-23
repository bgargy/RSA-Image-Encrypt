from flask import Flask, request, jsonify
from PIL import Image
import io
from flask_cors import CORS
import base64
from random import randrange, getrandbits

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# RSA Implementation
def power(a, d, n):
    ans = 1
    while d != 0:
        if d % 2 == 1:
            ans = ((ans % n) * (a % n)) % n
        a = ((a % n) * (a % n)) % n
        d >>= 1
    return ans

def MillerRabin(N, d):
    a = randrange(2, N - 1)
    x = power(a, d, N)
    if x == 1 or x == N - 1:
        return True
    else:
        while d != N - 1:
            x = ((x % N) * (x % N)) % N
            if x == 1:
                return False
            if x == N - 1:
                return True
            d <<= 1
    return False

def is_prime(N, K):
    if N == 3 or N == 2:
        return True
    if N <= 1 or N % 2 == 0:
        return False
    
    d = N - 1
    while d % 2 == 0:
        d //= 2

    for _ in range(K):
        if not MillerRabin(N, d):
            return False
    return True

def generate_prime_candidate(length):
    p = getrandbits(length)
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length):
    A = 4
    while not is_prime(A, 128):
        A = generate_prime_candidate(length)
    return A

def gcd(a, b):
    if a == 0:
        return b
    return gcd(b % a, a)

def gcd_extended(E, euler_totient):
    a1, a2, b1, b2, d1, d2 = 1, 0, 0, 1, euler_totient, E

    while d2 != 1:
        k = d1 // d2

        a1, a2 = a2, a1 - a2 * k
        b1, b2 = b2, b1 - b2 * k
        d1, d2 = d2, d1 - d2 * k

    D = b2
    if D > euler_totient:
        D %= euler_totient
    elif D < 0:
        D += euler_totient

    return D

def generate_keys(length):
    P = generate_prime_number(length)
    Q = generate_prime_number(length)
    N = P * Q
    euler_totient = (P - 1) * (Q - 1)
    E = generate_prime_number(4)
    while gcd(E, euler_totient) != 1:
        E = generate_prime_number(4)
    D = gcd_extended(E, euler_totient)
    return (E, N), (D, N)

# Generate RSA keys
public_key, private_key = generate_keys(16)  # Use larger primes for real use cases

@app.route('/encrypt_image', methods=['POST'])
def encrypt_image():
    file = request.files['image']
    image = Image.open(file).convert('RGB')
    image_bytes = image.tobytes()
    
    chunk_size = (public_key[1].bit_length() // 8) - 1
    encrypted_chunks = [power(int.from_bytes(image_bytes[i:i+chunk_size], byteorder='big'), public_key[0], public_key[1]).to_bytes((public_key[1].bit_length() + 7) // 8, byteorder='big') for i in range(0, len(image_bytes), chunk_size)]
    encrypted_image_data = b''.join(encrypted_chunks)
    
    encrypted_image_base64 = base64.b64encode(encrypted_image_data).decode('utf-8')
    return jsonify({'encrypted_image': encrypted_image_base64})

@app.route('/decrypt_image', methods=['POST'])
def decrypt_image():
    data = request.json
    encrypted_image_base64 = data.get('encrypted_image', '')
    encrypted_image_data = base64.b64decode(encrypted_image_base64)
    
    chunk_size = (private_key[1].bit_length() + 7) // 8
    decrypted_chunks = [power(int.from_bytes(encrypted_image_data[i:i+chunk_size], byteorder='big'), private_key[0], private_key[1]).to_bytes(chunk_size - 1, byteorder='big') for i in range(0, len(encrypted_image_data), chunk_size)]
    decrypted_image_data = b''.join(decrypted_chunks)
    
    image = Image.frombytes('RGB', (128, 128), decrypted_image_data)
    
    buffered = io.BytesIO()
    image.save(buffered, format="PNG")
    decrypted_image_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    return jsonify({'decrypted_image': decrypted_image_base64})

@app.route('/public_key', methods=['GET'])
def get_public_key():
    return jsonify({'e': public_key[0], 'n': public_key[1]})

if __name__ == '__main__':
    app.run(debug=True, port=8080)
