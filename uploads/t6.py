import sys
import os
import json
import hashlib
import datetime
from cryptography.fernet import Fernet
import oqs
import PyQt6
from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QFileDialog, 
    QTextEdit, QVBoxLayout, QComboBox, QMessageBox, QHBoxLayout, 
    QLineEdit, QDialog
)
from PyQt6.QtCore import Qt

class KeyManager:
    """Advanced key management system for PQC signatures"""
    def __init__(self, base_path='./keys'):
        # Ensure keys directory exists
        os.makedirs(base_path, exist_ok=True)
        self.base_path = base_path
        
        # Initialize encryption key for metadata
        self.encryption_key = self._load_or_generate_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)

    def _load_or_generate_encryption_key(self):
        """Load or generate an encryption key for metadata"""
        key_path = os.path.join(self.base_path, 'encryption.key')
        
        if os.path.exists(key_path):
            with open(key_path, 'rb') as key_file:
                return key_file.read()
        
        # Generate new encryption key
        encryption_key = Fernet.generate_key()
        with open(key_path, 'wb') as key_file:
            key_file.write(encryption_key)
        
        return encryption_key

    def generate_keypair(self, algorithm):
        """Generate keypair with metadata"""
        with oqs.Signature(algorithm) as signer:
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
        
        # Create metadata
        metadata = {
            'algorithm': algorithm,
            'generation_time': datetime.datetime.now().isoformat(),
            'key_id': hashlib.sha256(public_key).hexdigest()[:16]
        }
        
        return public_key, private_key, metadata

    def save_keypair(self, public_key, private_key, metadata):
        """Secure key storage with encryption and metadata"""
        # Create unique filename based on key ID
        key_id = metadata['key_id']
        
        # Save public key
        public_key_path = os.path.join(self.base_path, f'{key_id}_public.key')
        with open(public_key_path, 'wb') as f:
            f.write(public_key)
        
        # Save private key (encrypted)
        private_key_path = os.path.join(self.base_path, f'{key_id}_private.key')
        encrypted_private_key = self.cipher_suite.encrypt(private_key)
        with open(private_key_path, 'wb') as f:
            f.write(encrypted_private_key)
        
        # Save metadata
        metadata_path = os.path.join(self.base_path, f'{key_id}_metadata.json')
        encrypted_metadata = self.cipher_suite.encrypt(
            json.dumps(metadata).encode()
        )
        with open(metadata_path, 'wb') as f:
            f.write(encrypted_metadata)
        
        return key_id

    def load_keypair(self, key_id):
        """Secure key retrieval"""
        try:
            # Load public key
            public_key_path = os.path.join(self.base_path, f'{key_id}_public.key')
            with open(public_key_path, 'rb') as f:
                public_key = f.read()
            
            # Load and decrypt private key
            private_key_path = os.path.join(self.base_path, f'{key_id}_private.key')
            with open(private_key_path, 'rb') as f:
                encrypted_private_key = f.read()
                private_key = self.cipher_suite.decrypt(encrypted_private_key)
            
            # Load and decrypt metadata
            metadata_path = os.path.join(self.base_path, f'{key_id}_metadata.json')
            with open(metadata_path, 'rb') as f:
                encrypted_metadata = f.read()
                metadata = json.loads(
                    self.cipher_suite.decrypt(encrypted_metadata).decode()
                )
            
            return public_key, private_key, metadata
        
        except FileNotFoundError:
            raise ValueError(f"No keypair found for key ID: {key_id}")

class KeyGenerationDialog(QDialog):
    """Dialog for generating new key pairs"""
    def __init__(self, algorithms, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generate Key Pair")
        self.setModal(True)
        
        layout = QVBoxLayout()
        
        # Algorithm selection
        algo_layout = QHBoxLayout()
        algo_label = QLabel("Select Algorithm:")
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(algorithms)
        algo_layout.addWidget(algo_label)
        algo_layout.addWidget(self.algo_combo)
        layout.addLayout(algo_layout)
        
        # Key ID input
        key_id_layout = QHBoxLayout()
        key_id_label = QLabel("Key ID (optional):")
        self.key_id_input = QLineEdit()
        key_id_layout.addWidget(key_id_label)
        key_id_layout.addWidget(self.key_id_input)
        layout.addLayout(key_id_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        generate_btn = QPushButton("Generate")
        cancel_btn = QPushButton("Cancel")
        
        generate_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(generate_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def get_key_details(self):
        """Return selected algorithm and optional key ID"""
        return (
            self.algo_combo.currentText(), 
            self.key_id_input.text() or None
        )

class PQCCodeSigner(QWidget):
    def __init__(self):
        super().__init__()

        # Setup window
        self.setWindowTitle("Post-Quantum Code Signing")
        self.setGeometry(200, 200, 600, 450)

        # Initialize key manager
        self.key_manager = KeyManager()

        # Supported algorithms
        self.algorithms = [
            "Dilithium2",
            "Dilithium3",
            "Falcon-512",
            "SPHINCS+-SHA2-128s-simple"
        ]

        # Create UI
        self._create_ui()

        # Tracking variables
        self.file_path = None
        self.current_key_id = None

    def _create_ui(self):
        """Create user interface components"""
        layout = QVBoxLayout()

        # File selection section
        file_layout = QHBoxLayout()
        self.file_label = QLabel("Selected File:")
        self.file_path_display = QLineEdit()
        self.file_path_display.setReadOnly(True)
        self.select_file_btn = QPushButton("Select File")
        self.select_file_btn.clicked.connect(self.select_file)
        
        file_layout.addWidget(self.file_label)
        file_layout.addWidget(self.file_path_display)
        file_layout.addWidget(self.select_file_btn)
        layout.addLayout(file_layout)

        # Algorithm and key selection
        algo_key_layout = QHBoxLayout()
        algo_label = QLabel("Algorithm:")
        self.algo_selector = QComboBox()
        self.algo_selector.addItems(self.algorithms)
        
        key_label = QLabel("Key ID:")
        self.key_id_display = QLineEdit()
        self.key_id_display.setReadOnly(True)
        
        generate_key_btn = QPushButton("Generate Key")
        generate_key_btn.clicked.connect(self.generate_keypair)
        
        algo_key_layout.addWidget(algo_label)
        algo_key_layout.addWidget(self.algo_selector)
        algo_key_layout.addWidget(key_label)
        algo_key_layout.addWidget(self.key_id_display)
        algo_key_layout.addWidget(generate_key_btn)
        layout.addLayout(algo_key_layout)

        # Action buttons
        action_layout = QHBoxLayout()
        self.sign_btn = QPushButton("Sign File")
        self.verify_btn = QPushButton("Verify Signature")
        
        self.sign_btn.clicked.connect(self.sign_file)
        self.verify_btn.clicked.connect(self.verify_signature)
        
        action_layout.addWidget(self.sign_btn)
        action_layout.addWidget(self.verify_btn)
        layout.addLayout(action_layout)

        # Log display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        layout.addWidget(self.log_display)

        self.setLayout(layout)

    def select_file(self):
        """File selection dialog"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path = file_path
            self.file_path_display.setText(file_path)
            self.log(f"Selected file: {file_path}")

    def hash_file(self, file_path):
        """Generate SHA3-256 hash of file"""
        sha3 = hashlib.sha3_256()
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha3.update(chunk)
        return sha3.digest()

    def generate_keypair(self):
        """Open key generation dialog"""
        dialog = KeyGenerationDialog(self.algorithms, self)
        if dialog.exec():
            algorithm, custom_key_id = dialog.get_key_details()
            
            try:
                # Generate keypair
                public_key, private_key, metadata = self.key_manager.generate_keypair(algorithm)
                
                # Save keypair
                key_id = self.key_manager.save_keypair(public_key, private_key, metadata)
                
                # Update UI
                self.current_key_id = key_id
                self.key_id_display.setText(key_id)
                
                self.log(f"Generated {algorithm} key pair. Key ID: {key_id}")
            
            except Exception as e:
                QMessageBox.critical(self, "Key Generation Error", str(e))
                self.log(f"Key generation failed: {e}")

    def sign_file(self):
        if not self.file_path:
            QMessageBox.warning(self, "File Required", "Please select a file first.")
            return
        if not self.current_key_id:
            QMessageBox.warning(self, "Key Required", "Please generate a key pair first.")
            return

        try:
            # Retrieve metadata and selected algorithm
            _, _, metadata = self.key_manager.load_keypair(self.current_key_id)
            algorithm = metadata['algorithm']

            # Hash the file
            message = self.hash_file(self.file_path)

            # Generate a fresh key pair and sign the file
            with oqs.Signature(algorithm) as signer:
                public_key = signer.generate_keypair()
                signature = signer.sign(message)

            # Save signature
            sig_path = self.file_path + ".sig"
            with open(sig_path, "wb") as sig_file:
                sig_file.write(signature)

            # Save public key for verification
            pub_key_path = self.file_path + ".pub"
            with open(pub_key_path, "wb") as pub_file:
                pub_file.write(public_key)

            # Save metadata
            metadata_path = self.file_path + ".sigmeta"
            with open(metadata_path, "w") as meta_file:
                json.dump({
                    **metadata,
                    'signed_at': datetime.datetime.now().isoformat(),
                    'file_hash': message.hex()
                }, meta_file)

            self.log(f"File signed successfully with {algorithm}!")
            QMessageBox.information(self, "Signing Complete", "File signed successfully!")

        except Exception as e:
            QMessageBox.critical(self, "Signing Error", str(e))
            self.log(f"Signing failed: {e}")


    def verify_signature(self):
        """Verify file signature"""
        if not self.file_path:
            QMessageBox.warning(self, "File Required", "Please select a file first.")
            return

        try:
            # Read signature
            sig_path = self.file_path + ".sig"
            with open(sig_path, "rb") as sig_file:
                signature = sig_file.read()

            # Read metadata
            metadata_path = self.file_path + ".sigmeta"
            with open(metadata_path, "r") as meta_file:
                metadata = json.load(meta_file)

            algorithm = metadata.get('algorithm')
            key_id = metadata.get('key_id')

            if not algorithm or not key_id:
                QMessageBox.critical(self, "Metadata Error", "Invalid signature metadata.")
                self.log("❌ Verification failed: Metadata is missing or incorrect.")
                return

            # Retrieve public key
            pub_key_path = self.file_path + ".pub"
            with open(pub_key_path, "rb") as pub_file:
                public_key = pub_file.read()

            # Hash the file
            message = self.hash_file(self.file_path)

            # Verify signature
            with oqs.Signature(algorithm) as verifier:
                is_valid = verifier.verify(message, signature, public_key)

            if is_valid:
                self.log("✅ Signature VALID. File is authentic.")
                QMessageBox.information(self, "Verification", "Signature is VALID. File is authentic.")
            else:
                self.log("❌ Signature INVALID. File may be tampered.")
                QMessageBox.warning(self, "Verification", "Signature is INVALID. File may be tampered.")

        except Exception as e:
            QMessageBox.critical(self, "Verification Error", str(e))
            self.log(f"❌ Verification failed: {e}")



    def log(self, message):
        """Log messages to text display"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_display.append(f"[{timestamp}] {message}")

def main():
    app = QApplication(sys.argv)
    window = PQCCodeSigner()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()