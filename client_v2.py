from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import socket
import threading
import signal
import sys
import rsa
import logging
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

BUFFER_SIZE = 2048
flag = False
sockfd = None
name = ""
aes_key = None

exit_event = threading.Event()

def clear_line():
    """Clears the current line in the console."""
    sys.stdout.write('\r' + ' ' * 80 + '\r')
    sys.stdout.flush()

def prompt():
    """Displays the input prompt."""
    print("> ", end="", flush=True)

def exit_program(signum, frame):
    """Handles SIGINT (Ctrl+C) to initiate shutdown."""
    logging.info("\n[!] SIGINT received. Exiting...")
    exit_event.set() 
    if sockfd:
        try:
            # Attempt to send an encrypted exit message if possible
            if aes_key:
                encrypted_exit = encrypt_message("exit")
                if encrypted_exit:
                    sockfd.send(encrypted_exit.encode())
            else:
                sockfd.send("exit".encode())
        except (socket.error, rsa.pkcs1.CryptoError, ValueError, AttributeError, NameError) as e:
             logging.debug(f"Could not send final exit message: {e}") # Log as debug
        except Exception as e:
             logging.warning(f"Unexpected error sending final exit message: {e}")
  
def encrypt_message(message):
    """Encrypts a message using the shared AES key."""
    if not aes_key:
        logging.error("AES key not available for encryption.")
        return None
    try:
        iv = os.urandom(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_message = pad(message.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        # Prepend IV and Base64 encode
        return b64encode(iv + ciphertext).decode()
    except Exception as e:
        logging.error(f"Encryption error: {e}")
        return None

def send_msg_handler():
    """Handles sending user input messages, now encrypted."""
    global sockfd
    prompt()
    while not exit_event.is_set():
        try:
            msg = input()
            if exit_event.is_set():
                break

            if not msg:
                prompt()
                continue

            if msg.lower() == "exit":
                exit_event.set()
                # Encrypt the exit message before sending
                encrypted_msg = encrypt_message(msg)
                if encrypted_msg:
                    sockfd.send(encrypted_msg.encode())
                else:
                    # Fallback or error handling if encryption fails
                    logging.error("Failed to encrypt exit message. Sending plaintext (server might ignore).")
                    sockfd.send(msg.encode())
                break
            else:
                encrypted_msg = encrypt_message(msg)
                if encrypted_msg:
                    sockfd.send(encrypted_msg.encode())
                    prompt() # Show prompt again after sending
                else:
                    logging.error("Failed to encrypt message. Not sent.")
                    prompt()

        except EOFError:
            logging.info("EOF detected. Exiting...")
            exit_event.set()
            break
        except KeyboardInterrupt:
            logging.info("KeyboardInterrupt in send thread. Exiting...")
            exit_event.set()
            break
        except (socket.error, OSError) as e:
             if not exit_event.is_set():
                 logging.error(f"Socket error during send: {e}. Exiting...")
                 exit_event.set()
             break
        except Exception as e:
             if not exit_event.is_set():
                 logging.error(f"Unexpected error in send_msg_handler: {e}")
                 exit_event.set()
             break

    logging.debug("Send handler finished.")

def receive_msg_handler():
    """Handles receiving and decrypting messages from the server."""
    global sockfd, aes_key
    while not exit_event.is_set():
        try:
            encrypted_msg_b64 = sockfd.recv(BUFFER_SIZE)
            if not encrypted_msg_b64:
                logging.info("Server disconnected.")
                exit_event.set() # Signal exit
                break

            # Ensure AES key is available 
            if not aes_key:
                logging.warning("Received message before AES key is set. Ignoring.")
                continue

            try:
                # Decode Base64
                decoded_msg = b64decode(encrypted_msg_b64)
                iv = decoded_msg[:16]
                ciphertext = decoded_msg[16:]

                # Decrypt
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                plaintext_padded = cipher.decrypt(ciphertext)
                plaintext = unpad(plaintext_padded, AES.block_size)

                # Display message
                clear_line() 
                print(plaintext.decode())
                prompt() 

            except (ValueError, KeyError, IndexError) as e:
                 logging.warning(f"Error processing received data (possibly not encrypted or corrupted): {e}. Data: {encrypted_msg_b64[:50]}...")
                 clear_line()
                 prompt()
            except Exception as e:
                 logging.warning(f"Decryption error: {e}. Message: {encrypted_msg_b64[:50]}...")
                 clear_line()
                 prompt()

        except socket.timeout:
            logging.debug("Socket recv timeout.")
            continue
        except socket.error as e:
             if not exit_event.is_set():
                 logging.error(f"Socket error during receive: {e}. Exiting...")
                 exit_event.set()
             break 
        except Exception as e:
             if not exit_event.is_set():
                 logging.error(f"Unexpected error in receive_msg_handler: {e}")
                 exit_event.set()
             break

    logging.debug("Receive handler finished.")

def client():
    global sockfd, name, aes_key
    signal.signal(signal.SIGINT, exit_program)

    try:
        name = input("Enter your name (2-31 chars): ").strip()
        if not (2 <= len(name) <= 31):
            print("Invalid name length. Please try again.")
            sys.exit(1)
    except EOFError:
        print("\nExiting.")
        sys.exit(0)

    ip = "127.0.0.1"
    port = 4444

    try:
        sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logging.info(f"Connecting to {ip}:{port}...")
        sockfd.connect((ip, port))
        logging.info("Connected.")

        # --- Handshake ---
        # 1. Send Name
        sockfd.send(name.encode())
        logging.debug("Sent name.")

        # 2. Generate RSA keys & Send Public Key
        logging.debug("Generating RSA keys (2048 bits)...")
        public_key, private_key = rsa.newkeys(2048)
        sockfd.send(public_key.save_pkcs1())
        logging.debug("Sent public key.")

        # 3. Receive encrypted AES key
        encrypted_aes_key = sockfd.recv(512)
        if not encrypted_aes_key:
             raise ConnectionAbortedError("Server disconnected before sending AES key.")
        logging.debug(f"Received encrypted AES key ({len(encrypted_aes_key)} bytes).")

        # 4. Decrypt AES key
        aes_key = rsa.decrypt(encrypted_aes_key, private_key)
        logging.info("AES key received and decrypted successfully.")

        print("----- WELCOME TO CHATROOM ----- (Ctrl+C or type 'exit' to leave)")

        # Start send and receive threads
        send_thread = threading.Thread(target=send_msg_handler)
        recv_thread = threading.Thread(target=receive_msg_handler, daemon=True)
        # Make receiver daemon so it doesn't block exit if main thread finishes

        send_thread.start()
        recv_thread.start()

        # Wait for the send thread to finish Or wait for the exit event
        while send_thread.is_alive() and not exit_event.is_set():
            send_thread.join(timeout=0.5) 

        exit_event.set()
        recv_thread.join(timeout=1.0)

        logging.info("Exiting main thread.")

    except (socket.error, ConnectionRefusedError) as e:
        logging.error(f"Connection Error: {e}. Is the server running?")
    except rsa.pkcs1.DecryptionError as e:
         logging.error(f"Failed to decrypt AES key: {e}. Key mismatch or corruption?")
    except (ConnectionAbortedError, EOFError) as e:
         logging.error(f"Connection closed prematurely by server during setup: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        if sockfd:
            logging.debug("Closing socket.")
            sockfd.close()
        print("BYE")
        sys.exit(0) 

if __name__ == "__main__":
    client()
