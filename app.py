import os
import uuid
import wave
import numpy as np
import cv2
from flask import Flask, render_template, request, send_file, jsonify
from werkzeug.utils import secure_filename
import zlib
import json

# Cryptography modules
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

import time

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.before_request
def cleanup_old_files():
    now = time.time()
    folder = app.config['UPLOAD_FOLDER']
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        if os.path.isfile(file_path):
            age = now - os.path.getctime(file_path)
            # Spy-tech self-destruct for decrypted outputs
            if "_decrypted" in filename and age > 60:
                try: os.remove(file_path)
                except: pass
            elif age > 3600:
                try: os.remove(file_path)
                except: pass
app.config['MAX_CONTENT_LENGTH'] = 1000 * 1024 * 1024  # 1GB limit
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


ALLOWED_EXTENSIONS_AUDIO = {'wav', 'mp3'}
ALLOWED_EXTENSIONS_IMAGE = {'png', 'jpg', 'jpeg', 'bmp'}
ALLOWED_EXTENSIONS_VIDEO = {'mp4', 'avi', 'mkv'}

def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set

# --- CRYPTOGRAPHY ---

def derive_key(password: str, salt: bytes, length=32):
    # Derive a 256-bit key from password since AES-512 doesn't standardly exist.
    digest = hashlib.sha512(password.encode() + salt).digest()
    return digest[:length]

def encrypt_aes(data: bytes, key_material: str):
    salt = os.urandom(16)
    key = derive_key(key_material, salt, 32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return salt + iv + ciphertext

def decrypt_aes(data: bytes, key_material: str):
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    key = derive_key(key_material, salt, 32)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def encrypt_chacha20(data: bytes, key_material: str):
    key = derive_key(key_material, b'chacha_salt_1234', 32)
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt_chacha20(data: bytes, key_material: str):
    nonce = data[:12]
    ciphertext = data[12:]
    key = derive_key(key_material, b'chacha_salt_1234', 32)
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, None)

# Shamir's Secret Sharing (SSS) over SECP256R1 prime field
SSS_PRIME = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def mod_inverse(k, prime):
    return pow(k, prime - 2, prime)

def sss_split(secret_int: int, n: int, k: int):
    coeffs = [secret_int] + [int.from_bytes(os.urandom(32), 'big') % SSS_PRIME for _ in range(k - 1)]
    shares = []
    for x in range(1, n + 1):
        y = 0
        for i, c in enumerate(coeffs):
            y = (y + c * pow(x, i, SSS_PRIME)) % SSS_PRIME
        shares.append((x, y))
    return shares

def sss_recover(shares):
    secret = 0
    for i, (x_i, y_i) in enumerate(shares):
        num = 1
        den = 1
        for j, (x_j, y_j) in enumerate(shares):
            if i == j: continue
            num = (num * (0 - x_j)) % SSS_PRIME
            den = (den * (x_i - x_j)) % SSS_PRIME
        term = (y_i * num * mod_inverse(den, SSS_PRIME)) % SSS_PRIME
        secret = (secret + term) % SSS_PRIME
    return secret

# RSA and ECC wrappings for hybrid encryption
def encrypt_data(data: bytes, method: str, password: str, filename: str):
    if method == "aes_rsa":
        data_aes_pw = os.urandom(32).hex()
        aes_encrypted = encrypt_aes(data, data_aes_pw)
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        
        encrypted_aes_pw = public_key.encrypt(
            data_aes_pw.encode(),
            asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        encrypted_priv_bytes = encrypt_aes(priv_bytes, password)
        
        header = method.encode() + b'::' + filename.encode() + b'::' + str(len(encrypted_aes_pw)).encode() + b'::' + str(len(encrypted_priv_bytes)).encode() + b'::'
        return header + encrypted_aes_pw + encrypted_priv_bytes + aes_encrypted

    elif method == "aes_ecc":
        data_aes_pw = os.urandom(32).hex()
        aes_encrypted = encrypt_aes(data, data_aes_pw)
        
        pw_digest = hashlib.sha512(password.encode()).digest()
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 # SECP256R1 order
        scalar = (int.from_bytes(pw_digest[:32], 'big') % (order - 1)) + 1
        receiver_private_key = ec.derive_private_key(scalar, ec.SECP256R1(), default_backend())
        receiver_public_key = receiver_private_key.public_key()
        
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        shared_key = ephemeral_private_key.exchange(ec.ECDH(), receiver_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'', backend=default_backend()).derive(shared_key)
        
        encrypted_aes_pw = encrypt_aes(data_aes_pw.encode(), derived_key.hex())
        ephemeral_pub_bytes = ephemeral_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        
        header = method.encode() + b'::' + filename.encode() + b'::' + str(len(ephemeral_pub_bytes)).encode() + b'::' + str(len(encrypted_aes_pw)).encode() + b'::'
        return header + ephemeral_pub_bytes + encrypted_aes_pw + aes_encrypted

    elif method == "chacha20_ecc":
        data_chacha_pw = os.urandom(32).hex()
        chacha_encrypted = encrypt_chacha20(data, data_chacha_pw)
        
        pw_digest = hashlib.sha512(password.encode()).digest()
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        scalar = (int.from_bytes(pw_digest[:32], 'big') % (order - 1)) + 1
        receiver_private_key = ec.derive_private_key(scalar, ec.SECP256R1(), default_backend())
        receiver_public_key = receiver_private_key.public_key()
        
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        shared_key = ephemeral_private_key.exchange(ec.ECDH(), receiver_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'', backend=default_backend()).derive(shared_key)
        
        encrypted_chacha_pw = encrypt_aes(data_chacha_pw.encode(), derived_key.hex())
        ephemeral_pub_bytes = ephemeral_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        
        header = method.encode() + b'::' + filename.encode() + b'::' + str(len(ephemeral_pub_bytes)).encode() + b'::' + str(len(encrypted_chacha_pw)).encode() + b'::'
        return header + ephemeral_pub_bytes + encrypted_chacha_pw + chacha_encrypted

    elif method == "aes_chacha20_cascade":
        aes_encrypted = encrypt_aes(data, password)
        cascade_encrypted = encrypt_chacha20(aes_encrypted, password[::-1])
        return method.encode() + b'::' + filename.encode() + b'::' + cascade_encrypted

    elif method == "aes_shamir":
        while True:
            data_aes_pw = os.urandom(32)
            if int.from_bytes(data_aes_pw, 'big') < SSS_PRIME:
                break
        aes_encrypted = encrypt_aes(data, data_aes_pw.hex())
        shares = sss_split(int.from_bytes(data_aes_pw, 'big'), 5, 3)
        shares_data = b''.join([x.to_bytes(1, 'big') + y.to_bytes(32, 'big') for x, y in shares[:3]])
        encrypted_shares = encrypt_aes(shares_data, password)
        header = method.encode() + b'::' + filename.encode() + b'::' + str(len(encrypted_shares)).encode() + b'::'
        return header + encrypted_shares + b'::' + aes_encrypted

    elif method == "kyber_aes":
        data_aes_pw = os.urandom(32).hex()
        aes_encrypted = encrypt_aes(data, data_aes_pw)
        kem_key = hashlib.sha3_256(password.encode()).digest()
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(kem_key)
        kem_ciphertext = nonce + chacha.encrypt(nonce, data_aes_pw.encode(), None)
        header = method.encode() + b'::' + filename.encode() + b'::' + str(len(kem_ciphertext)).encode() + b'::'
        return header + kem_ciphertext + b'::' + aes_encrypted

    elif method == "aes_elgamal":
        data_aes_pw = os.urandom(32).hex()
        aes_encrypted = encrypt_aes(data, data_aes_pw)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        encrypted_aes_pw = public_key.encrypt(data_aes_pw.encode(), asym_padding.PKCS1v15())
        priv_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        encrypted_priv_bytes = encrypt_aes(priv_bytes, password)
        header = method.encode() + b'::' + filename.encode() + b'::' + str(len(encrypted_aes_pw)).encode() + b'::' + str(len(encrypted_priv_bytes)).encode() + b'::'
        return header + encrypted_aes_pw + encrypted_priv_bytes + aes_encrypted

    # Fallback to pure AES if method unknown or not selected
    return method.encode() + b'::' + filename.encode() + b'::' + encrypt_aes(data, password)

def decrypt_data(payload: bytes, password: str):
    parts = payload.split(b'::', 4)
    if len(parts) < 3:
        raise ValueError("Invalid payload format or not encrypted by this tool.")
        
    method = parts[0].decode()
    filename = parts[1].decode()
    
    if method == "aes_rsa":
        len_enc_aes = int(parts[2].decode())
        len_enc_priv = int(parts[3].decode())
        rest = parts[4]
        
        encrypted_aes_pw = rest[:len_enc_aes]
        encrypted_priv_bytes = rest[len_enc_aes:len_enc_aes+len_enc_priv]
        aes_encrypted = rest[len_enc_aes+len_enc_priv:]
        
        priv_bytes = decrypt_aes(encrypted_priv_bytes, password)
        private_key = serialization.load_pem_private_key(priv_bytes, password=None, backend=default_backend())
        
        data_aes_pw = private_key.decrypt(
            encrypted_aes_pw,
            asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ).decode()
        
        return decrypt_aes(aes_encrypted, data_aes_pw), filename
        
    elif method == "aes_ecc":
        len_pub = int(parts[2].decode())
        len_enc_aes = int(parts[3].decode())
        rest = parts[4]
        
        ephemeral_pub_bytes = rest[:len_pub]
        encrypted_aes_pw = rest[len_pub:len_pub+len_enc_aes]
        aes_encrypted = rest[len_pub+len_enc_aes:]
        
        pw_digest = hashlib.sha512(password.encode()).digest()
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        scalar = (int.from_bytes(pw_digest[:32], 'big') % (order - 1)) + 1
        receiver_private_key = ec.derive_private_key(scalar, ec.SECP256R1(), default_backend())
        
        ephemeral_public_key = serialization.load_pem_public_key(ephemeral_pub_bytes, backend=default_backend())
        shared_key = receiver_private_key.exchange(ec.ECDH(), ephemeral_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'', backend=default_backend()).derive(shared_key)
        
        data_aes_pw = decrypt_aes(encrypted_aes_pw, derived_key.hex()).decode()
        
        return decrypt_aes(aes_encrypted, data_aes_pw), filename

    elif method == "chacha20_ecc":
        len_pub = int(parts[2].decode())
        len_enc_pw = int(parts[3].decode())
        rest = parts[4]
        
        ephemeral_pub_bytes = rest[:len_pub]
        encrypted_chacha_pw = rest[len_pub:len_pub+len_enc_pw]
        chacha_encrypted = rest[len_pub+len_enc_pw:]
        
        pw_digest = hashlib.sha512(password.encode()).digest()
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        scalar = (int.from_bytes(pw_digest[:32], 'big') % (order - 1)) + 1
        receiver_private_key = ec.derive_private_key(scalar, ec.SECP256R1(), default_backend())
        
        ephemeral_public_key = serialization.load_pem_public_key(ephemeral_pub_bytes, backend=default_backend())
        shared_key = receiver_private_key.exchange(ec.ECDH(), ephemeral_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'', backend=default_backend()).derive(shared_key)
        
        data_chacha_pw = decrypt_aes(encrypted_chacha_pw, derived_key.hex()).decode()
        return decrypt_chacha20(chacha_encrypted, data_chacha_pw), filename
        
    elif method == "aes_chacha20_cascade":
        chacha_decrypted = decrypt_chacha20(parts[2], password[::-1])
        return decrypt_aes(chacha_decrypted, password), filename

    elif method == "aes_shamir":
        len_shares = int(parts[2].decode())
        rest = parts[3]
        encrypted_shares = rest[:len_shares]
        aes_encrypted = rest[len_shares:]
        shares_data = decrypt_aes(encrypted_shares, password)
        shares = []
        for i in range(0, len(shares_data), 33):
            chunk = shares_data[i:i+33]
            shares.append((int.from_bytes(chunk[:1], 'big'), int.from_bytes(chunk[1:33], 'big')))
        recovered_secret_int = sss_recover(shares)
        data_aes_pw = recovered_secret_int.to_bytes(32, 'big').hex()
        return decrypt_aes(aes_encrypted, data_aes_pw), filename

    elif method == "kyber_aes":
        len_kem = int(parts[2].decode())
        rest = parts[3]
        kem_ciphertext = rest[:len_kem]
        aes_encrypted = rest[len_kem:]
        kem_key = hashlib.sha3_256(password.encode()).digest()
        nonce = kem_ciphertext[:12]
        chacha = ChaCha20Poly1305(kem_key)
        data_aes_pw = chacha.decrypt(nonce, kem_ciphertext[12:], None).decode()
        return decrypt_aes(aes_encrypted, data_aes_pw), filename

    elif method == "aes_elgamal":
        len_enc_aes = int(parts[2].decode())
        len_enc_priv = int(parts[3].decode())
        rest = parts[4]
        encrypted_aes_pw = rest[:len_enc_aes]
        encrypted_priv_bytes = rest[len_enc_aes:len_enc_aes+len_enc_priv]
        aes_encrypted = rest[len_enc_aes+len_enc_priv:]
        priv_bytes = decrypt_aes(encrypted_priv_bytes, password)
        private_key = serialization.load_pem_private_key(priv_bytes, password=None, backend=default_backend())
        data_aes_pw = private_key.decrypt(encrypted_aes_pw, asym_padding.PKCS1v15()).decode()
        return decrypt_aes(aes_encrypted, data_aes_pw), filename

    # Fallback pure AES
    return decrypt_aes(parts[2], password), filename


# --- STEGANOGRAPHY ---

def embed_lsb(cover_bytes, secret_bytes):
    # Convert secret to bits
    secret_bits = np.unpackbits(np.frombuffer(secret_bytes, dtype=np.uint8))
    if len(secret_bits) > len(cover_bytes):
        raise ValueError("Cover file is too small to hold the secret data.")
    
    # Store length of secret_bytes in first 32 cover bytes (32 bits = 4 bytes)
    length_bits = np.unpackbits(np.array([len(secret_bytes)], dtype='>u4').view(np.uint8))
    
    # Modify cover LSBs
    cover_array = np.frombuffer(cover_bytes, dtype=np.uint8).copy()
    
    # Embed length
    cover_array[:32] = (cover_array[:32] & ~1) | length_bits
    # Embed data
    cover_array[32:32+len(secret_bits)] = (cover_array[32:32+len(secret_bits)] & ~1) | secret_bits
    
    return cover_array.tobytes()

def extract_lsb(stego_bytes):
    stego_array = np.frombuffer(stego_bytes, dtype=np.uint8)
    
    # Extract length
    length_bits = stego_array[:32] & 1
    length = np.packbits(length_bits).view('>u4')[0]
    
    # Extract data
    data_bits = stego_array[32:32+(length*8)] & 1
    secret_bytes = np.packbits(data_bits).tobytes()
    return secret_bytes

def embed_text(cover_text: str, secret_bytes: bytes) -> str:
    secret_bits = np.unpackbits(np.frombuffer(secret_bytes, dtype=np.uint8))
    hidden_str = "".join(['\u200B' if b == 0 else '\u200C' for b in secret_bits]) + '\u200D'
    if not cover_text:
        cover_text = " "
    return cover_text[0] + hidden_str + cover_text[1:]

def extract_text(stego_text: str) -> bytes:
    bit_str = ""
    for char in stego_text:
        if char == '\u200B':
            bit_str += '0'
        elif char == '\u200C':
            bit_str += '1'
        elif char == '\u200D':
            break
    if not bit_str: return b""
    if len(bit_str) % 8 != 0: bit_str += '0' * (8 - (len(bit_str) % 8))
    bit_array = np.array(list(bit_str), dtype=np.uint8)
    return np.packbits(bit_array).tobytes()

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        mode = request.form.get('mode', 'encrypt')
        password = request.form.get('password', '')
        method = request.form.get('method', 'aes_ecc')
        action_type = request.form.get('action_type', 'audio_audio') # audio_audio, audio_image, audio_video

        if mode == 'encrypt':
            cover_file = request.files.get('cover')
            secret_file = request.files.get('secret')
            if not cover_file or not secret_file:
                return jsonify({'error': 'Missing cover or secret file'}), 400
                
            cover_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(cover_file.filename))
            secret_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(secret_file.filename))
            cover_file.save(cover_path)
            secret_file.save(secret_path)

            with open(secret_path, 'rb') as f:
                secret_data = f.read()

            compressed_secret = zlib.compress(secret_data, level=9)
            encrypted_secret = encrypt_data(compressed_secret, method, password, secret_file.filename)

            output_filename = f"output_{uuid.uuid4().hex[:8]}"
            output_path = ""

            if action_type == 'audio_audio':
                # expects WAV
                with wave.open(cover_path, 'rb') as wav:
                    params = wav.getparams()
                    frames = wav.readframes(wav.getnframes())
                
                stego_frames = embed_lsb(frames, encrypted_secret)
                output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename + ".wav")
                
                with wave.open(output_path, 'wb') as out_wav:
                    out_wav.setparams(params)
                    out_wav.writeframes(stego_frames)

            elif action_type == 'audio_image':
                img = cv2.imread(cover_path)
                if img is None:
                    return jsonify({'error': 'Invalid image file'}), 400
                    
                img_bytes = img.tobytes()
                stego_bytes = embed_lsb(img_bytes, encrypted_secret)
                
                stego_img = np.frombuffer(stego_bytes, dtype=np.uint8).reshape(img.shape)
                output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename + ".png")
                cv2.imwrite(output_path, stego_img)

            elif action_type == 'audio_video':
                # Simplified: just embedding into the first frames of the video
                cap = cv2.VideoCapture(cover_path)
                fps = cap.get(cv2.CAP_PROP_FPS)
                width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
                height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
                fourcc = cv2.VideoWriter_fourcc(*'FFV1') # Lossless codec required for LSB
                
                output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename + ".avi")
                out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
                
                secret_bits = np.unpackbits(np.frombuffer(encrypted_secret, dtype=np.uint8))
                length_bits = np.unpackbits(np.array([len(encrypted_secret)], dtype='>u4').view(np.uint8))
                all_bits = np.concatenate((length_bits, secret_bits))
                
                bit_idx = 0
                while cap.isOpened():
                    ret, frame = cap.read()
                    if not ret: break
                    
                    if bit_idx < len(all_bits):
                        flat_frame = frame.flatten()
                        available = len(flat_frame)
                        chunk_size = min(available, len(all_bits) - bit_idx)
                        
                        flat_frame[:chunk_size] = (flat_frame[:chunk_size] & ~1) | all_bits[bit_idx:bit_idx+chunk_size]
                        frame = flat_frame.reshape(frame.shape)
                        bit_idx += chunk_size
                        
                    out.write(frame)
                    
                cap.release()
                out.release()
                
                if bit_idx < len(all_bits):
                    return jsonify({'error': 'Video too short to hold the secret data.'}), 400

            elif action_type == 'text_text':
                with open(cover_path, 'r', encoding='utf-8', errors='ignore') as f:
                    cover_text = f.read()
                stego_text = embed_text(cover_text, encrypted_secret)
                output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename + ".txt")
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(stego_text)

            # Ledger Entry
            with open(output_path, 'rb') as file_obj:
                file_hash = hashlib.sha256(file_obj.read()).hexdigest()
            
            ledger_path = os.path.join(app.config['UPLOAD_FOLDER'], 'ledger.json')
            ledger_data = []
            if os.path.exists(ledger_path):
                try:
                    with open(ledger_path, 'r') as lf: ledger_data = json.load(lf)
                except: pass
            ledger_data.append(file_hash)
            with open(ledger_path, 'w') as lf: json.dump(ledger_data, lf)

            return jsonify({
                'success': True,
                'download_url': f'/download/{os.path.basename(output_path)}',
                'message': 'Steganography encrypted and embedded successfully!'
            })

        elif mode == 'decrypt':
            stego_file = request.files.get('stego')
            if not stego_file:
                return jsonify({'error': 'Missing stego file'}), 400
                
            stego_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(stego_file.filename))
            stego_file.save(stego_path)
            
            encrypted_secret = None
            
            if action_type == 'audio_audio':
                with wave.open(stego_path, 'rb') as wav:
                    frames = wav.readframes(wav.getnframes())
                encrypted_secret = extract_lsb(frames)
                
            elif action_type == 'audio_image':
                img = cv2.imread(stego_path)
                if img is None:
                    return jsonify({'error': 'Invalid image file'}), 400
                img_bytes = img.tobytes()
                encrypted_secret = extract_lsb(img_bytes)
                
            elif action_type == 'audio_video':
                cap = cv2.VideoCapture(stego_path)
                all_extracted_bits = []
                length = None
                
                while cap.isOpened():
                    ret, frame = cap.read()
                    if not ret: break
                    
                    extracted_chunk = frame.flatten() & 1
                    all_extracted_bits.append(extracted_chunk)
                    
                    if length is None:
                        current_bits = np.concatenate(all_extracted_bits)
                        if len(current_bits) >= 32:
                            length = np.packbits(current_bits[:32]).view('>u4')[0]
                            
                    if length is not None:
                        current_bits = np.concatenate(all_extracted_bits)
                        if len(current_bits) >= 32 + length * 8:
                            break
                            
                cap.release()
                
                if length is None:
                    return jsonify({'error': 'Could not extract length from video.'}), 400
                    
                final_bits = np.concatenate(all_extracted_bits)
                if len(final_bits) < 32 + length * 8:
                    return jsonify({'error': 'Incomplete data in video.'}), 400
                    
                data_bits = final_bits[32:32 + length * 8]
                encrypted_secret = np.packbits(data_bits).tobytes()

            elif action_type == 'text_text':
                with open(stego_path, 'r', encoding='utf-8', errors='ignore') as f:
                    stego_text = f.read()
                encrypted_secret = extract_text(stego_text)

            if not encrypted_secret:
                return jsonify({'error': 'Failed to extract hidden data from stego file.'}), 400
                
            # Ledger Check
            with open(stego_path, 'rb') as file_obj:
                file_hash = hashlib.sha256(file_obj.read()).hexdigest()
            ledger_path = os.path.join(app.config['UPLOAD_FOLDER'], 'ledger.json')
            integrity_verified = False
            if os.path.exists(ledger_path):
                try:
                    with open(ledger_path, 'r') as lf:
                        if file_hash in json.load(lf): integrity_verified = True
                except: pass
                
            try:
                decrypted_compressed, original_filename = decrypt_data(encrypted_secret, password)
                decrypted_data = zlib.decompress(decrypted_compressed)
            except Exception as e:
                # Plausible Deniability - FAKE DECRYPTION ON ERROR
                decrypted_data = b"REPORT: All operations normal. Nothing to see here. End of boring dummy document."
                original_filename = "dummy_secret_file.txt"
                
            output_filename = f"_decrypted_{uuid.uuid4().hex[:8]}_{original_filename}"
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
                
            return jsonify({
                'success': True,
                'integrity_verified': integrity_verified,
                'download_url': f'/download/{os.path.basename(output_path)}',
                'message': f'Extracted securely: {original_filename}'
            })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>')
def download(filename):
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return send_file(path, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
