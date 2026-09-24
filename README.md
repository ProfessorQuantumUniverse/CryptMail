# CryptMail

A Chrome Extension for sending and receiving multi-layer encrypted emails through Gmail.

<!-- INSTALL BUTTONS START -->
<p align="center">
  <a href="https://github.com/ProfessorQuantumUniverse/CryptMail/releases/latest"><img src="https://img.shields.io/badge/Download-Chrome%20Extension-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Download the extension" height="40"></a>
  <a href="#installation"><img src="https://img.shields.io/badge/How%20to-install-555555?style=for-the-badge&logo=github&logoColor=white" alt="How to install" height="40"></a>
</p>
<!-- INSTALL BUTTONS END -->

## How It Works

1. **Key Exchange** – You and your contact agree on a shared passphrase (out of band).
2. **Encrypt** – When composing in Gmail, CryptMail encrypts your message with 100 rounds of AES-256-GCM, each round using a fresh random IV and salt derived from the shared passphrase via PBKDF2.
3. **Send** – The extension replaces the plaintext in Gmail's compose field with the encrypted envelope and sends it.
4. **Decrypt** – When you open a received email, the extension automatically detects the encrypted envelope, decrypts it using the stored key for that sender, and displays the plaintext.

## Installation

1. Clone or download this repository.
2. Open `chrome://extensions/` in Chrome.
3. Enable **Developer mode** (toggle in the top right).
4. Click **Load unpacked** and select the repository folder.
5. The CryptMail icon appears in your toolbar.

## Usage

### Add a Contact Key

1. Click the CryptMail icon in the toolbar.
2. Enter the contact's email address and the shared passphrase.
3. Click **Save Key**.

### Send an Encrypted Email

1. Compose a new email in Gmail.
2. Write your message normally.
3. Click the **🔒 Encrypt & Send** button that appears in the compose toolbar.
4. The extension encrypts the message and sends it.

### Read an Encrypted Email

When you open an email containing a CryptMail envelope, the extension automatically decrypts and displays the plaintext (if you have the sender's key stored). A toggle button lets you switch between the decrypted and encrypted views.

## Encryption Details

- **Algorithm**: AES-256-GCM
- **Key Derivation**: PBKDF2 with SHA-256, 600,000 iterations
- **Rounds**: 100 (configurable) layers of encryption
- **Randomness**: Each round uses a unique random 16-byte salt and 12-byte IV

## Development

### Run Tests

```bash
npm test
```

### Project Structure

```
├── manifest.json          # Chrome Extension manifest (MV3)
├── src/
│   ├── crypto.js          # Multi-layer AES-GCM encryption/decryption
│   ├── keystore.js        # Per-contact key storage (chrome.storage)
│   ├── content.js         # Gmail content script (UI integration)
│   ├── content.css        # Content script styles
│   ├── popup.html         # Extension popup UI
│   └── popup.js           # Popup logic
├── icons/                 # Extension icons
└── test/
    └── crypto.test.js     # Crypto module unit tests
```

## License

GNU General Public License v3.0 – see [LICENSE](LICENSE) for details.
