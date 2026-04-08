# StegoVault

StegoVault is a Python-based GUI application that provides secure data hiding and transfer using steganography and encryption techniques. It supports hiding messages and files inside images and audio, detecting hidden data, and securely sending files using OTP-based verification.

---

## Features

### Audio Steganography

* Hide encrypted messages inside WAV audio files
* Extract hidden messages using a password

### Image Steganography

* Hide encrypted text inside images (PNG/JPG)
* Retrieve hidden messages securely

### File-in-Image Steganography

* Embed text files inside images
* Extract hidden files using a password

### Steganography Detector

* Detect possible hidden data in images and audio files

### Secure Media Transfer

* Send stego files via email
* OTP-based verification
* QR code encrypted password sharing

### OTP Verification

* Time-based OTP (valid for 120 seconds)
* Secure password retrieval

---

## Technologies Used

* Python
* Tkinter (GUI)
* Pillow (Image Processing)
* Cryptography (Fernet Encryption)
* Wave (Audio Processing)
* SMTP (Email Sending)
* QR Code generation

---

## Project Structure

```id="s7d6l1"
StegoVault/
│
├── main.py
├── images/
│   ├── robo_open.jpg
│   ├── boyhacker.jpeg
│   ├── hackroom.jpeg
```

---

## Installation

1. Clone the repository:

```id="r6n8u3"
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

2. Install dependencies:

```id="j1p4x8"
pip install pillow cryptography qrcode
```

---

## Running the Application

```id="p3v9k2"
python main.py
```

---

## Usage

1. Open the application

2. Select a module:

   * Audio Steganography
   * Image Steganography
   * File in Image Steganography
   * Steganography Detector
   * Secure Media Transfer
   * OTP Verification

3. Choose action (Encrypt or Decrypt where applicable)

4. Enter required inputs

5. Use a 16-character password

---

## Notes

* Only WAV files are supported for audio
* Only PNG, JPG, and JPEG formats are supported for images
* Only TXT files are supported for file embedding
* Password must be exactly 16 characters
* File size is limited by the capacity of the image or audio

---

## Security

* Uses Fernet encryption for secure data protection
* OTP-based authentication with expiry time
* Encrypted password sharing via QR code
* Secure email transmission

---


