# Secure StegoSuite | Advanced Hybrid Cryptography & Steganography

## 🛡️ Best Description
**Secure StegoSuite** is a cutting-edge, high-security web application that merges multi-layered hybrid cryptography with advanced steganography. It allows users to imperceptibly conceal highly sensitive, encrypted data inside various ordinary-looking media files (Audio, Images, Video, and Text). 

Designed for utmost paranoia and secure communications, it leverages military-grade encryption methodologies including cascaded stream ciphers, Shamir's Secret Sharing, and simulated Post-Quantum (Kyber) KEM wrappers. All file tampering is actively monitored through a local ledger system, while decrypted files are programmed with a "spy-tech" self-destruct sequence to ensure no lingering traces on the server.

## ✨ Key Features
- **Unbreakable Hybrid Cryptography**: Choose from 7 powerful encryption suites.
  - *AES 256 + ECC (Elliptic Curve Cryptography)*
  - *AES 256 + RSA 2048*
  - *ChaCha20 + ECC*
  - *Cascaded Encryption (AES 256 + ChaCha20)*
  - *Post-Quantum Simulation (AES + CRYSTALS-Kyber wrapper)*
  - *Shamir's Secret Splitting (Threshold recovery)*
  - *AES + ElGamal/DH*
- **Omni-Media LSB Steganography**: Seamlessly embed encrypted payloads into varying cover formats.
  - Audio (`.wav`)
  - Images (`.png`, `.bmp`)
  - Video (`.avi`)
  - Text (`.txt` using zero-width characters)
- **Data Integrity Ledger**: Automatically generates SHA-256 hashes of stego-files to a local ledger. Alerts the user upon extraction if the file was tampered with during transit.
- **Plausible Deniability**: Silent failure handling that spawns dummy files if a decryption attempt is forced or fails.
- **Ephemeral Sandbox**: Extracted files and temporary uploads auto-destruct (expire) after a short duration to ensure maximum OPSEC.
- **Premium Glassmorphism UI**: A beautifully crafted, responsive, and dynamic user interface offering an unparalleled user experience.

## 🚀 Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone https://github.com/DDMA-010245/GUI-STEGNOGRAPHY.git
   cd GUI-STEGNOGRAPHY
   ```

2. **Install dependencies:**
   Ensure you have Python 3.8+ installed, then run:
   ```bash
   pip install flask cryptography uuid wave numpy opencv-python werkzeug
   ```

3. **Run the Application:**
   ```bash
   python app.py
   ```

4. **Access the Web UI:**
   Open your browser and navigate to `http://localhost:5000`

## 🧩 Architecture Snapshot
- **Backend:** Python (Flask)
- **Cryptography:** Python `cryptography` library, `hashlib`
- **Data Manipulation:** `numpy`, `cv2` (OpenCV), `wave`, `zlib`
- **Frontend:** Vanilla HTML/CSS/JS (No heavy frameworks, sheer raw performance)

## ⚠️ Disclaimer
This tool is built for educational, research, and legitimate privacy purposes. The authors take no responsibility for any misuse of the application.
