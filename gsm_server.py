from __future__ import annotations

import json
import secrets
import socket
import threading
from typing import Dict

from gsm_algorithms import a3_a8_comp128_like, a5_decrypt


class GSMAuthServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 9999):
        self.host = host
        self.port = port
        # IMSI -> Ki (hex)
        self.subscribers: Dict[str, str] = {
            "250011234567890": "00112233445566778899AABBCCDDEEFF",
            "250019876543210": "FFEEDDCCBBAA99887766554433221100",
        }
        self._server_socket: socket.socket | None = None
        self._running = False

    def start(self):
        self._running = True
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)
        print(f"[SERVER] Listening on {self.host}:{self.port}")

        while self._running:
            try:
                conn, addr = self._server_socket.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()

    def stop(self):
        self._running = False
        if self._server_socket:
            self._server_socket.close()

    def _send(self, conn: socket.socket, payload: dict):
        conn.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode())

    def _recv(self, conn: socket.socket) -> dict:
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(4096)
            if not chunk:
                raise ConnectionError("client disconnected")
            data += chunk
        return json.loads(data.decode().strip())

    def _handle_client(self, conn: socket.socket, addr):
        print(f"[SERVER] Connection from {addr}")
        try:
            hello = self._recv(conn)
            if hello.get("type") != "auth_request":
                self._send(conn, {"type": "error", "msg": "Expected auth_request"})
                return

            imsi = hello.get("imsi")
            if imsi not in self.subscribers:
                self._send(conn, {"type": "auth_reject", "reason": "Unknown IMSI"})
                return

            ki = bytes.fromhex(self.subscribers[imsi])
            rand = secrets.token_bytes(16)
            sres_expected, kc = a3_a8_comp128_like(ki, rand)

            self._send(conn, {"type": "auth_challenge", "rand": rand.hex()})
            resp = self._recv(conn)
            if resp.get("type") != "auth_response":
                self._send(conn, {"type": "auth_reject", "reason": "Expected auth_response"})
                return

            sres_client = bytes.fromhex(resp.get("sres", ""))
            if sres_client != sres_expected:
                self._send(conn, {"type": "auth_reject", "reason": "Bad SRES"})
                return

            self._send(conn, {"type": "auth_accept", "kc_hint": kc.hex()[:8] + "..."})

            secure_msg = self._recv(conn)
            if secure_msg.get("type") == "secure_data":
                frame = int(secure_msg["frame"])
                cipher = bytes.fromhex(secure_msg["ciphertext"])
                plain = a5_decrypt(kc, frame, cipher)
                text = plain.decode(errors="replace")
                print(f"[SERVER] Decrypted from {imsi}: {text}")
                self._send(conn, {"type": "secure_ack", "received": text})
        except Exception as e:
            self._send(conn, {"type": "error", "msg": str(e)})
        finally:
            conn.close()


if __name__ == "__main__":
    server = GSMAuthServer()
    try:
        server.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
