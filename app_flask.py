from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from datetime import datetime
from collections import defaultdict
import os
import socket
import threading
import rsa
import logging
import signal
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
connection_attempts = defaultdict(list) 
CONNECTION_LIMIT_WINDOW = 60 
MAX_CONNECTIONS_PER_WINDOW = 3
active_usernames = set()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global variables to store client connections
clients = {}  
stop_events = {}

def encrypt_message(message, aes_key):
    """Encrypts a message using the shared AES key."""
    if not aes_key:
        logging.error("AES key not available for encryption.") 
        return None
    try:
        iv = os.urandom(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_message = pad(message.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        return b64encode(iv + ciphertext).decode()
    except Exception as e:
        logging.error(f"Encryption error: {e}")
        return None

def decrypt_message(encrypted_msg_b64, aes_key):
    """Decrypts a message using the shared AES key."""
    if not aes_key:
        logging.error("AES key not available for decryption.")
        return None
    try:
        decoded_msg = b64decode(encrypted_msg_b64)
        iv = decoded_msg[:16]
        ciphertext = decoded_msg[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext_padded = cipher.decrypt(ciphertext)
        plaintext = unpad(plaintext_padded, AES.block_size)
        return plaintext.decode()
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return f"[System Error: Could not decrypt message]"

# Chat server functions
def receive_messages(sid, sockfd, aes_key, stop_event):
    """Background thread function to receive messages from the chat server."""
    logging.info(f"Started receive thread for client {sid}")
    username = clients[sid].get("username", "Unknown")
    
    while not stop_event.is_set() and sockfd:
        try:
            encrypted_msg = sockfd.recv(2048)
            if not encrypted_msg:
                logging.info("Server disconnected")
                socketio.emit('system_message', {"message": "Server disconnected"}, room=sid, namespace='/')
                break
            
            decrypted_msg = decrypt_message(encrypted_msg, aes_key)
            if decrypted_msg:
                logging.info(f"Received message: {decrypted_msg[:50]}...")
                socketio.emit('chat_message', {"message": decrypted_msg}, room=sid, namespace='/')
            
        except socket.timeout:
            continue
        except Exception as e:
            if not stop_event.is_set():
                logging.error(f"Error in receive thread: {e}")
                socketio.emit('system_message', {"message": f"Connection error: {e}"}, room=sid, namespace='/')
            break
    
    logging.info(f"Receive thread ended for client {sid}")
    if not stop_event.is_set():
        socketio.emit('system_message', {"message": "Connection lost"}, room=sid, namespace='/')
        disconnect_client(sid)

def can_connect(ip_address, username):
    """Check if an IP address can connect based on recent attempts and username uniqueness"""
    now = datetime.now().timestamp()
    if username in active_usernames:
        logging.warning(f"Username '{username}' is already connected")
        return False, f"Username '{username}' is already in use"
    connection_attempts[ip_address] = [
        timestamp for timestamp in connection_attempts[ip_address]
        if now - timestamp < CONNECTION_LIMIT_WINDOW
    ]
    if len(connection_attempts[ip_address]) >= MAX_CONNECTIONS_PER_WINDOW:
        oldest_attempt = connection_attempts[ip_address][0]
        wait_time = int(CONNECTION_LIMIT_WINDOW - (now - oldest_attempt))
        logging.warning(f"IP {ip_address} exceeded connection limit. Must wait {wait_time} seconds")
        return False, f"Too many connection attempts. Please wait {wait_time} seconds"
    connection_attempts[ip_address].append(now)
    return True, "OK"

def connect_to_server(username, sid):
    """Connect to the chat server for a specific client."""
    try:
        ip_address = request.remote_addr
        can_connect_result, message = can_connect(ip_address, username)
        if not can_connect_result:
            return False, message
        logging.info(f"Connecting as {username}...")
        sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sockfd.settimeout(10) 
    
        ip = "127.0.0.1"
        port = 4444
        sockfd.connect((ip, port))
        sockfd.send(username.encode())
        public_key, private_key = rsa.newkeys(2048)
        sockfd.send(public_key.save_pkcs1())
        encrypted_aes_key = sockfd.recv(512)
        if not encrypted_aes_key:
            raise ConnectionError("Server disconnected during key exchange")
        aes_key = rsa.decrypt(encrypted_aes_key, private_key)
        sockfd.settimeout(0.5) 
        stop_event = threading.Event()
        clients[sid] = {
            "socket": sockfd,
            "aes_key": aes_key,
            "username": username,
            "ip_address": ip_address
        }
        stop_events[sid] = stop_event
        active_usernames.add(username)
        socketio.start_background_task(
            receive_messages,
            sid, sockfd, aes_key, stop_event
        )
        logging.info(f"Connection successful for {username} (sid: {sid})")
        return True, "Connected successfully"
    
    except Exception as e:
        logging.error(f"Connection error: {e}")
        return False, f"Connection error: {e}"

def disconnect_client(sid):
    """Disconnect a client from the chat server."""
    logging.info(f"Disconnecting client {sid}")
    
    if sid not in clients:
        return
    client_info = clients[sid]
    sockfd = client_info.get("socket")
    aes_key = client_info.get("aes_key")
    username = client_info.get("username")
    
    if username in active_usernames:
        active_usernames.remove(username)

    if sid in stop_events:
        stop_events[sid].set()
    
    if sockfd and aes_key:
        try:
            encrypted_exit = encrypt_message("exit", aes_key)
            if encrypted_exit:
                sockfd.send(encrypted_exit.encode())
        except Exception as e:
            logging.error(f"Error sending exit message: {e}")

    if sockfd:
        try:
            sockfd.close()
        except Exception as e:
            logging.error(f"Error closing socket: {e}")
    
    if sid in clients:
        del clients[sid]
    if sid in stop_events:
        del stop_events[sid]
    
    logging.info(f"Client {sid} disconnected")

@app.route('/')
def index():
    return render_template('chat.html')

@socketio.on('connect')
def handle_connect():
    logging.info(f"Client connected: {request.sid}")
    emit('connected', {"message": "Connected to server"})

@socketio.on('disconnect')
def handle_disconnect():
    logging.info(f"Client disconnected: {request.sid}")
    disconnect_client(request.sid)

@socketio.on('login')
def handle_login(data):
    username = data.get('username')
    if not username or len(username) < 2 or len(username) > 31:
        emit('login_response', {"success": False, "message": "Username must be between 2-31 characters"})
        return
    
    success, message = connect_to_server(username, request.sid)
    emit('login_response', {"success": success, "message": message})
    
    if success:
        emit('system_message', {"message": f"Connected as {username}. Your messages are encrypted with AES-256."})

@socketio.on('send_message')
def handle_message(data):
    sid = request.sid
    message = data.get('message')
    
    if not message or sid not in clients:
        return
    
    client_info = clients[sid]
    sockfd = client_info.get("socket")
    aes_key = client_info.get("aes_key")
    username = client_info.get("username")
    
    if not sockfd or not aes_key:
        emit('system_message', {"message": "Not connected to server"})
        return
    
    try:
        encrypted_msg = encrypt_message(message, aes_key)
        if not encrypted_msg:
            emit('system_message', {"message": "Failed to encrypt message"})
            return
        
        sockfd.send(encrypted_msg.encode())
        logging.info(f"Message sent by {username}: {message[:50]}...")
        emit('chat_message', {"message": f"{username}: {message}", "self": True})
        
    except Exception as e:
        logging.error(f"Error sending message: {e}")
        emit('system_message', {"message": f"Error sending message: {e}"})
        if isinstance(e, (socket.error, ConnectionError, BrokenPipeError)):
            disconnect_client(sid)

@socketio.on('logout')
def handle_logout():
    disconnect_client(request.sid)
    emit('logout_response', {"success": True})

def clean_shutdown(signal_num, frame):
    """Handle keyboard interrupts by cleanly shutting down the server"""
    print("\nShutting down the server...")
    client_ids = list(clients.keys())
    for sid in client_ids:
        try:
            socketio.emit('system_message', 
                         {"message": "Server is shutting down. Disconnecting."}, 
                         room=sid, namespace='/')
            disconnect_client(sid)
        except Exception as e:
            logging.error(f"Error disconnecting client {sid} during shutdown: {e}")
    
    logging.info("All clients disconnected. Exiting.")
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, clean_shutdown)
    print("Starting Flask server at http://127.0.0.1:5000")
    print("Press Ctrl+C to shut down the server")
    try:
        socketio.run(app, host='127.0.0.1', port=5000, debug=True)
    except KeyboardInterrupt:
        clean_shutdown(None, None) 