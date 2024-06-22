from flask import Flask, request, jsonify
import rsa
from PIL import Image
import io
from flask_cors import CORS
import base64

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Generate RSA keys
(public_key, private_key) = rsa.newkeys(512)

@app.route('/encrypt_image', methods=['POST'])
def encrypt_image():
    file = request.files['image']
    image = Image.open(file)
    image_bytes = image.tobytes()
    
    # Encrypt the image data
    chunk_size = 53  # RSA can encrypt data in chunks less than the key size (key size in bytes - padding overhead)
    encrypted_chunks = [rsa.encrypt(image_bytes[i:i+chunk_size], public_key) for i in range(0, len(image_bytes), chunk_size)]
    encrypted_image_data = b''.join(encrypted_chunks)
    
    # Convert to base64 to send as a response
    encrypted_image_base64 = base64.b64encode(encrypted_image_data).decode('utf-8')
    return jsonify({'encrypted_image': encrypted_image_base64})

@app.route('/decrypt_image', methods=['POST'])
def decrypt_image():
    data = request.json
    encrypted_image_base64 = data.get('encrypted_image', '')
    encrypted_image_data = base64.b64decode(encrypted_image_base64)
    
    # Decrypt the image data
    chunk_size = 64  # RSA decrypts data in chunks equal to the key size
    decrypted_chunks = [rsa.decrypt(encrypted_image_data[i:i+chunk_size], private_key) for i in range(0, len(encrypted_image_data), chunk_size)]
    decrypted_image_data = b''.join(decrypted_chunks)
    
    # Convert bytes back to an image
    image_size = (128, 128)  # Example image size, you may need to adjust this based on the actual image size
    image = Image.frombytes('RGB', image_size, decrypted_image_data)
    
    # Convert to base64 to send as a response
    buffered = io.BytesIO()
    image.save(buffered, format="PNG")
    decrypted_image_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    return jsonify({'decrypted_image': decrypted_image_base64})

@app.route('/public_key', methods=['GET'])
def get_public_key():
    return jsonify({'e': public_key.e, 'n': public_key.n})

if __name__ == '__main__':
    app.run(debug=True, port=8080)
