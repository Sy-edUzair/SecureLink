from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import socket
import threading
import signal
import sys
import rsa
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

NUM_CLIENTS = 10
BUFFER_SIZE = 2048
client_count = 0
clients = {}
client_lock = threading.Lock()
user_id_counter = 0
user_id_lock = threading.Lock()


class Client:
    def __init__(self, sockfd, address, uid, name, rsa_public_key):
        self.sockfd = sockfd
        self.address = address
        self.uid = uid
        self.name = name
        self.rsa_public_key = rsa_public_key
        self.aes_key = os.urandom(32) 

        try:
            encrypted_aes_key = rsa.encrypt(self.aes_key, self.rsa_public_key)
            self.sockfd.send(encrypted_aes_key)
            logging.info(f"Sent AES key to {self.name} ({self.uid})")
        except (rsa.pkcs1.VerificationError, socket.error) as e:
            logging.error(f"Failed to send AES key to {self.name} ({self.uid}): {e}")
            raise ConnectionAbortedError("Failed to send AES key")

    def encrypt_message(self, message):
        try:
            iv = os.urandom(16)
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            padded_message = pad(message.encode(), AES.block_size)
            ciphertext = cipher.encrypt(padded_message)
            # Prepend IV to the ciphertext and encode in Base64
            return b64encode(iv + ciphertext).decode()
        except Exception as e:
            logging.error(f"Encryption error for message to {self.name}: {e}")
            return None

    def decrypt_message(self, encrypted_msg_b64):
        try:
            decoded_msg = b64decode(encrypted_msg_b64)
            iv = decoded_msg[:16]
            ciphertext = decoded_msg[16:]
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            plaintext_padded = cipher.decrypt(ciphertext)
            plaintext = unpad(plaintext_padded, AES.block_size)
            return plaintext.decode()
        except (ValueError, KeyError, IndexError) as e:
            logging.warning(f"Client {self.name} ({self.uid}): Error processing received data (B64/IV/Ciphertext): {e}")
            return None
        except Exception as e:
            logging.warning(f"Client {self.name} ({self.uid}): Decryption error: {e}")
            return None


def get_next_user_id():
    global user_id_counter
    with user_id_lock:
        user_id_counter += 1
        return user_id_counter


def add_client(client):
    global client_count
    with client_lock:
        if client_count < NUM_CLIENTS:
            clients[client.uid] = client
            client_count += 1
            return True
        return False


def remove_client(uid):
    global client_count
    with client_lock:
        if uid in clients:
            del clients[uid]
            client_count -= 1


def send_message(message, sender_id):
    with client_lock:
        client_ids = list(clients.keys())
        for uid in client_ids:
            if uid == sender_id:
                continue

            client = clients.get(uid)
            if not client:
                continue

            encrypted_message = client.encrypt_message(message)
            if encrypted_message:
                try:
                    client.sockfd.send(encrypted_message.encode())
                except socket.error as e:
                    logging.warning(f"Failed to send message to {client.name} ({client.uid}): {e}. Removing client.")
                except Exception as e:
                    logging.error(f"Unexpected error sending message to {client.name} ({client.uid}): {e}")
            else:
                logging.error(f"Failed to encrypt message for {client.name} ({client.uid}).")


def handle_client(client_socket, client_address):
    global user_id
    name = None
    client = None
    uid = -1

    try:
        try:
            name_bytes = client_socket.recv(32)
            if not name_bytes: raise ConnectionAbortedError("Client disconnected during name recv")
            name = name_bytes.decode().strip()
            if not (2 <= len(name) <= 31):
                logging.warning(f"Invalid name length from {client_address}. Name: '{name}'")
                client_socket.send("Invalid name. Disconnecting.".encode())
                raise ValueError("Invalid name length")

            logging.info(f"Received name: {name} from {client_address}")

            pubkey_data = client_socket.recv(2048)
            if not pubkey_data: raise ConnectionAbortedError("Client disconnected during pubkey recv")
            rsa_public_key = rsa.PublicKey.load_pkcs1(pubkey_data)
            logging.info(f"Received public key from {name}")

        except (socket.error, ConnectionAbortedError, ValueError, rsa.pkcs1.LoadError) as e:
            logging.error(f"Handshake failed for {client_address}: {e}")
            client_socket.close()
            return
        except Exception as e:
            logging.error(f"Unexpected handshake error for {client_address}: {e}")
            client_socket.close()
            return

        uid = get_next_user_id()
        try:
            client = Client(client_socket, client_address, uid, name, rsa_public_key)
        except ConnectionAbortedError as e:
            logging.error(f"Failed to initialize client {name}: {e}")
            client_socket.close()
            return
        except Exception as e:
            logging.error(f"Unexpected error initializing client {name}: {e}")
            client_socket.close()
            return

        if not add_client(client):
            logging.warning(f"Client limit reached. Rejecting connection from {name} ({client_address})")
            try:
                client.sockfd.send(client.encrypt_message("Server full. Disconnecting.").encode())
            except Exception:
                pass
            client_socket.close()
            return

        join_message = f"{name} has joined the chat"
        logging.info(join_message)
        send_message(join_message, client.uid)

        while True:
            try:
                # Receive encrypted data from the client
                encrypted_data_b64 = client_socket.recv(BUFFER_SIZE)
                if not encrypted_data_b64:
                    # Client disconnected gracefully or connection lost
                    logging.info(f"Client {name} ({client.uid}) disconnected (received empty data).")
                    break # Exit loop
                message = client.decrypt_message(encrypted_data_b64)

                if message is None:
                    # Decryption failed
                    logging.warning(f"Could not decrypt message from {name} ({client.uid}). Skipping.")
                    continue

                message = message.strip()
                if not message: 
                    continue

                logging.debug(f"Decrypted from {name} ({client.uid}): {message[:50]}...")

                if message.lower() == "exit":
                     logging.info(f"{name} ({client.uid}) requested exit.")
                     break 
                broadcast_message = f"{name}: {message}"
                logging.info(f"Broadcasting: {broadcast_message}")
                send_message(broadcast_message, client.uid)

            except socket.timeout:
                logging.warning(f"Socket timeout for {name} ({client.uid}).")
                continue
            except socket.error as e:
                logging.error(f"Socket error for {name} ({client.uid}): {e}")
                break
            except UnicodeDecodeError:
                logging.warning(f"Received non-UTF8 data from {name} ({client.uid}). Ignoring.")
                continue
            except Exception as e:
                logging.error(f"Unexpected error in handle_client for {name} ({client.uid}): {e}")
                break

    finally:
        if client:
            leave_message = f"{name} has left the chat"
            logging.info(leave_message)
            remove_client(client.uid)
            send_message(leave_message, client.uid)
        try:
            client_socket.close()
        except socket.error:
            pass
        logging.debug(f"Socket closed for connection from {client_address}")


def shutdown_server(signal_num, frame):
    logging.info("[!] SIGINT received. Shutting down server...")
    shutdown_message = "Server is shutting down. Disconnecting."
    with client_lock:
        client_ids = list(clients.keys())
        logging.info(f"Notifying {len(client_ids)} clients...")
        for uid in client_ids:
            client = clients.get(uid)
            if client:
                try:
                    encrypted_shutdown_msg = client.encrypt_message(shutdown_message)
                    if encrypted_shutdown_msg:
                        client.sockfd.send(encrypted_shutdown_msg.encode())
                        logging.debug(f"Sent shutdown notification to {client.name} ({uid})")
                    else:
                        logging.warning(f"Could not encrypt shutdown message for {client.name} ({uid})")
                    client.sockfd.close()
                except socket.error as e:
                    logging.warning(f"Socket error while notifying/closing {client.name} ({uid}): {e}")
                except Exception as e:
                    logging.error(f"Unexpected error notifying/closing {client.name} ({uid}): {e}")
        clients.clear()
        global client_count
        client_count = 0
    logging.info("Server shutdown complete.")
    sys.exit(0)


def server():
    ip = "127.0.0.1"
    port = 4444
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((ip, port))
        server_socket.listen(NUM_CLIENTS)
        logging.info(f"-------- WELCOME TO CHATROOM (Listening on {ip}:{port}) --------")
    except socket.error as e:
        logging.critical(f"BIND ERROR: {e}. Is port {port} already in use?")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"Unexpected error starting server: {e}")
        sys.exit(1)

    try:
        while True:
            with client_lock:
                current_clients = client_count

            if current_clients >= NUM_CLIENTS:
                logging.warning("Client limit reached! Waiting for a slot...")
                threading.Event().wait(0.5)
                continue

            try:
                client_socket, client_address = server_socket.accept()
                logging.info(f"Accepted connection from {client_address}")

                thread = threading.Thread(
                    target=handle_client, args=(client_socket, client_address), daemon=True
                )
                thread.start()

            except socket.error as e:
                logging.error(f"Error accepting connection: {e}")
                continue
            except Exception as e:
                logging.error(f"Unexpected error in main accept loop: {e}")
                break

    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt received in main loop (should be handled by SIGINT).")
    finally:
        logging.info("Closing server socket.")
        server_socket.close()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown_server)
    server()
