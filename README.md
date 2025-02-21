# Anti-Piracy Challenge

![Build Status](https://img.shields.io/badge/build-passing-brightgreen) ![License](https://img.shields.io/badge/license-MIT-blue)

## Project Description

The "Anti-Piracy Challenge" is a Python-based application that implements watermark embedding, LSB steganography, encryption, and blockchain technology to protect digital content. It provides a secure method to encode messages within images, detect watermarks, and create immutable records using blockchain.

## Features

- **Digital Watermarking:** Embed and detect watermarks in images using DCT techniques.
- **LSB Steganography:** Encode and decode encrypted messages within image pixels.
- **Encryption:** Secure messages using AES encryption before embedding.
- **Blockchain Integration:** Create a blockchain to store content fingerprints securely.
- **Graphical User Interface (GUI):** Built with Tkinter for an intuitive user experience.
- **Content Fingerprinting:** Generate perceptual hashes for tracking authenticity.

## Table of Contents

- [Prerequisites](#prerequisites)
- [How to Install and Run the Project](#how-to-install-and-run-the-project)
- [How to Use the Project](#how-to-use-the-project)
- [Screenshots/Media](#screenshotsmedia)
- [Future Improvements](#future-improvements)
- [Contributing](#contributing)
- [License](#license)
- [Credits](#credits)
- [Author](#author)
- [Connect with Me](#connect-with-me)

## Prerequisites

- Python 3.8 or higher
- Required Python libraries:
  - `tkinter`
  - `PIL (Pillow)`
  - `opencv-python`
  - `numpy`
  - `cryptography`
  - `imagehash`
  - `pytesseract` (for optional OCR support)

## How to Install and Run the Project

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/Anti-Piracy-Challenge.git
   ```
2. **Navigate to the project directory:**
   ```bash
   cd Anti-Piracy-Challenge
   ```
3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Run the application:**
   ```bash
   python Anti-Piracy Challenge.py
   ```

## How to Use the Project

1. **Upload an Image:** Load an image file for processing.
2. **Add Watermark:** Enter text to embed within the image using DCT.
3. **Encode a Secret Message:** Enter a message, encrypt it, and hide it in an image.
4. **Decode a Secret Message:** Extract and decrypt the hidden message from an image.
5. **Mine a Block:** Generate a unique fingerprint of the image and store it in the blockchain.
6. **View Blockchain:** Inspect the blockchain ledger to verify stored fingerprints.

## Video Recording

You can view the video recording of the project in action by clicking on the link below:
[Video Recording](https://github.com/DarshanKagi/Anti-Piracy-Challenge/blob/e880670a2cda3958a9fbafa63f045d56aa1de6a0/Recording.mp4)

## Future Improvements

- Implement a web-based interface for remote usage.
- Add AI-based watermark detection techniques.
- Expand blockchain functionality for decentralized storage.
- Improve encryption techniques with quantum-resistant algorithms.

## Contributing

Contributions are welcome! Feel free to fork this repository, make your changes, and submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Credits

- Developed with guidance from various cybersecurity and blockchain resources.

## Author

Darshan S Kagi  
Email: darshankagi04@gmail.com

## Connect with Me

- [LinkedIn](https://www.linkedin.com/in/darshan-kagi-938836255/)
- [GitHub](https://github.com/DarshanKagi)
