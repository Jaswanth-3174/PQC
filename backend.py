import sys
import os
import json
import hashlib
import datetime
from cryptography.fernet import Fernet
import oqs
from oqs.oqs import Signature  # Explicitly import Signature from oqs.oqs
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__, static_folder='static')

# Verify oqs installation
try:
    print(f"oqs module location: {oqs.__file__}")
    print(f"Signature class available: {Signature is not None}")
    if hasattr(oqs, 'get_enabled_sig_mechanisms'):
        print("Supported signature algorithms:", oqs.get_enabled_sig_mechanisms())
    else:
        print("Note: get_enabled_sig_mechanisms not directly available in top-level oqs")
except Exception as e:
    print(f"Warning: {e}")

class KeyManager:
    """Advanced key management system for PQC signatures"""
    def __init__(self, base_path='./keys'):
        os.makedirs(base_path, exist_ok=True)
        self.base_path = base_path
        self.encryption_key = self._load_or_generate_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)

    def _load_or_generate_encryption_key(self):
        key_path = os.path.join(self.base_path, 'encryption.key')
        if os.path.exists(key_path):
            with open(key_path, 'rb') as key_file:
                return key_file.read()
        encryption_key = Fernet.generate_key()
        with open(key_path, 'wb') as key_file:
            key_file.write(encryption_key)
        return encryption_key

    def generate_keypair(self, algorithm):
        try:
            signer = Signature(algorithm)  # Don’t use context manager so we can keep the instance
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
            metadata = {
                'algorithm': algorithm,
                'generation_time': datetime.datetime.now().isoformat(),
                'key_id': hashlib.sha256(public_key).hexdigest()[:16]
            }
            return public_key, private_key, metadata, signer  # Return signer instance
        except Exception as e:
            raise ValueError(f"Failed to generate keypair with {algorithm}: {str(e)}")

    def save_keypair(self, public_key, private_key, metadata):
        key_id = metadata['key_id']
        public_key_path = os.path.join(self.base_path, f'{key_id}_public.key')
        with open(public_key_path, 'wb') as f:
            f.write(public_key)
        private_key_path = os.path.join(self.base_path, f'{key_id}_private.key')
        encrypted_private_key = self.cipher_suite.encrypt(private_key)
        with open(private_key_path, 'wb') as f:
            f.write(encrypted_private_key)
        metadata_path = os.path.join(self.base_path, f'{key_id}_metadata.json')
        encrypted_metadata = self.cipher_suite.encrypt(json.dumps(metadata).encode())
        with open(metadata_path, 'wb') as f:
            f.write(encrypted_metadata)
        return key_id

    def load_keypair(self, key_id):
        try:
            public_key_path = os.path.join(self.base_path, f'{key_id}_public.key')
            with open(public_key_path, 'rb') as f:
                public_key = f.read()
            private_key_path = os.path.join(self.base_path, f'{key_id}_private.key')
            with open(private_key_path, 'rb') as f:
                encrypted_private_key = f.read()
                private_key = self.cipher_suite.decrypt(encrypted_private_key)
            metadata_path = os.path.join(self.base_path, f'{key_id}_metadata.json')
            with open(metadata_path, 'rb') as f:
                encrypted_metadata = f.read()
                metadata = json.loads(self.cipher_suite.decrypt(encrypted_metadata).decode())
            return public_key, private_key, metadata
        except FileNotFoundError:
            raise ValueError(f"No keypair found for key ID: {key_id}")

class PQCCodeSigner:
    def __init__(self):
        self.key_manager = KeyManager()
        self.file_path = None
        self.current_key_id = None
        self.signers = {}  # Store Signature instances by key_id

    def hash_file(self, file_path):
        sha3 = hashlib.sha3_256()
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha3.update(chunk)
        return sha3.digest()

    def sign_file(self):
        if not self.file_path or not self.current_key_id:
            raise ValueError("File path or key ID not set")
        if self.current_key_id not in self.signers:
            raise ValueError(f"No signer instance available for key ID: {self.current_key_id}")
        
        signer = self.signers[self.current_key_id]
        message = self.hash_file(self.file_path)
        public_key, _, metadata = self.key_manager.load_keypair(self.current_key_id)
        
        signature = signer.sign(message)  # Use the stored signer instance
        
        sig_path = self.file_path + ".sig"
        with open(sig_path, "wb") as sig_file:
            sig_file.write(signature)
        
        pub_key_path = self.file_path + ".pub"
        with open(pub_key_path, "wb") as pub_file:
            pub_file.write(public_key)
        
        metadata_path = self.file_path + ".sigmeta"
        with open(metadata_path, "w") as meta_file:
            json.dump({
                **metadata,
                'signed_at': datetime.datetime.now().isoformat(),
                'file_hash': message.hex()
            }, meta_file)

    def verify_signature(self):
        if not self.file_path:
            raise ValueError("File path not set")
        sig_path = self.file_path + ".sig"
        metadata_path = self.file_path + ".sigmeta"
        
        with open(sig_path, "rb") as sig_file:
            signature = sig_file.read()
        
        with open(metadata_path, "r") as meta_file:
            metadata = json.load(meta_file)
        
        algorithm = metadata.get('algorithm')
        pub_key_path = self.file_path + ".pub"
        with open(pub_key_path, "rb") as pub_file:
            public_key = pub_file.read()
        
        message = self.hash_file(self.file_path)
        
        with Signature(algorithm) as verifier:
            is_valid = verifier.verify(message, signature, public_key)
        
        return is_valid

# Initialize the signer
signer = PQCCodeSigner()

# Serve the front-end
@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

# Serve static files (CSS, JS)
@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(app.static_folder, path)

# API Endpoints
@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    try:
        data = request.json
        algorithm = data.get('algorithm')
        if algorithm not in ["Dilithium2", "Dilithium3", "Falcon-512", "SPHINCS+-SHA2-128s-simple"]:
            return jsonify({'error': 'Invalid algorithm'}), 400
        public_key, private_key, metadata, signature_instance = signer.key_manager.generate_keypair(algorithm)
        key_id = signer.key_manager.save_keypair(public_key, private_key, metadata)
        signer.current_key_id = key_id
        signer.signers[key_id] = signature_instance  # Store the signer instance
        return jsonify({'keyId': key_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sign-file', methods=['POST'])
def sign_file():
    try:
        if 'file' not in request.files or 'keyId' not in request.form:
            return jsonify({'error': 'File and keyId required'}), 400
        file = request.files['file']
        key_id = request.form['keyId']
        
        os.makedirs('uploads', exist_ok=True)
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)
        
        signer.file_path = file_path
        signer.current_key_id = key_id
        signer.sign_file()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify-signature', methods=['POST'])
def verify_signature():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'File required'}), 400
        file = request.files['file']
        
        os.makedirs('uploads', exist_ok=True)
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)
        
        signer.file_path = file_path
        is_valid = signer.verify_signature()
        
        return jsonify({'isValid': is_valid})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)