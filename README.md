# Secure Chat Application

A secure end-to-end encrypted chat application built with Flask and SocketIO that provides secure communication through a hybrid RSA/AES encryption system.
![image](https://github.com/user-attachments/assets/e29e5b65-8500-4aec-8ef3-224b8d25b182)
![image](https://github.com/user-attachments/assets/96fcb44b-82d0-4dd8-aec5-d7ba7a7b8fbf)


## Features

- **End-to-End Encryption**: Messages are encrypted using AES-256 in CBC mode.
- **Secure Key Exchange**: RSA-2048 for secure exchange of AES keys.
- **Real-time Communication**: WebSocket-based messaging for instant delivery.
- **Rate Limiting**: Protection against brute force and DoS attacks.
- **Username Validation**: Ensures unique usernames on the platform.
- **Logging System**: Comprehensive event logging for troubleshooting.
- **Clean Shutdown**: Graceful termination with proper resource cleanup.

## Architecture

This application implements a two-tier socket architecture with end-to-end encryption:

### Communication Layers
- **Browser ↔ Flask Server**: Uses Socket.IO (WebSockets with fallbacks) for real-time web communication.
- **Flask Server ↔ Chat Server**: Uses standard TCP sockets for backend communication.

### Component Roles
- **Web Client (Browser)**:
  - Connects to Flask server using Socket.IO
  - Provides user interface for sending/receiving messages
  - Handles login/logout events

- **Flask Server (Proxy)**:
  - Acts as a secure proxy between web clients and chat server
  - Manages user sessions and connection states
  - Implements rate limiting and security measures
  - Handles encryption/decryption of all messages:
    - Uses RSA-2048 for initial AES key exchange
    - Uses AES-256 (CBC mode) for all message encryption
  - Maintains background threads to receive messages from chat server

- **Chat Server**:
  - Accepts TCP socket connections from the Flask server
  - Handles username registration
  - Broadcasts messages to connected clients
  - No knowledge of message contents (receives pre-encrypted data)

### Data Flow
1. User logs in via browser, connecting to Flask server via Socket.IO
2. Flask server establishes TCP connection to chat server
3. RSA key exchange occurs to securely share AES key
4. User sends message through browser
5. Flask server encrypts message with AES and forwards to chat server
6. Chat server broadcasts encrypted message to all clients
7. Each client's Flask server decrypts received messages
8. Decrypted messages are sent to browsers via Socket.IO

### Encryption Process
- **Key Exchange**: RSA-2048 asymmetric encryption
- **Message Encryption**: AES-256 symmetric encryption in CBC mode with random IV
- **Message Format**: Base64-encoded string containing IV + encrypted content

#### About CBC Mode
CBC (Cipher Block Chaining) is an encryption mode used with AES that provides additional security:

- **How It Works**:
  - Divides messages into fixed-size blocks (16 bytes for AES)
  - Each block is XORed with the previous ciphertext block before encryption
  - Uses a random Initialization Vector (IV) for the first block

- **Security Benefits**:
  - Prevents identical plaintext blocks from producing identical ciphertext
  - Makes patterns in the original data impossible to detect
  - Adds randomization even when encrypting the same message multiple times
  - Provides better security than simpler modes like ECB (Electronic Codebook)

- **Implementation Details**:
  - Each message uses a new random IV (16 bytes)
  - IV is prepended to the ciphertext and encoded in Base64
  - Padding is applied to ensure messages align with block boundaries

## Requirements

- Python 3.6+
- Flask
- Flask-SocketIO
- PyCryptodome
- rsa

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/secure-chat.git
   cd secure-chat
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Start the chat server:
   ```
   python server_v2.py
   ```

4. Start the Flask application:
   ```
   python app_flask.py
   ```

5. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

## Usage

1. Enter a username (2-31 characters) to log in
2. Start sending encrypted messages
3. All communications are secured with AES-256 encryption
4. Use the logout button to properly terminate your session

## Security Features

- **Hybrid Encryption**: RSA for key exchange, AES for message encryption
- **Secure Key Management**: Unique session keys generated for each connection
- **Connection Rate Limiting**: Prevents server flooding
- **Proper Error Handling**: Secure error messages that don't leak information

## Limitations

- The chat server is currently configured to run locally (127.0.0.1)
- Message history is not stored - messages are only available during active sessions


## Disclaimer

This application is provided for educational purposes only. Always perform proper security audits before using encryption software in production environments. 
