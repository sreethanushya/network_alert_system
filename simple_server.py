# simple_server.py
import socket, threading

HOST = "0.0.0.0"
PORT = 9000

def handle_client(conn, addr):
    try:
        data = conn.recv(1024)
        conn.sendall(b"OK")
    except:
        pass
    finally:
        conn.close()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(50)
    print(f"[server] Listening on {HOST}:{PORT}")
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("[server] stopping")
    finally:
        s.close()

if __name__ == "__main__":
    main()
