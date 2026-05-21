from __future__ import annotations

import json
import socket
import tkinter as tk
from tkinter import messagebox, ttk

from gsm_algorithms import a3_a8, a5_encrypt


class GSMClientGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("GSM Security Demo: MS Client")
        self.root.geometry("760x520")

        self.host_var = tk.StringVar(value="127.0.0.1")
        self.port_var = tk.StringVar(value="9999")
        self.imsi_var = tk.StringVar(value="250011234567890")
        self.ki_var = tk.StringVar(value="00112233445566778899AABBCCDDEEFF")
        self.frame_var = tk.StringVar(value="1")

        self._build()

    def _build(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        fields = [
            ("Server host", self.host_var),
            ("Server port", self.port_var),
            ("IMSI", self.imsi_var),
            ("Ki (hex)", self.ki_var),
            ("Frame #", self.frame_var),
        ]
        for i, (label, var) in enumerate(fields):
            ttk.Label(top, text=label).grid(row=i, column=0, sticky="w", padx=4, pady=2)
            ttk.Entry(top, textvariable=var, width=50).grid(row=i, column=1, sticky="ew", padx=4, pady=2)

        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="Payload text").grid(row=len(fields), column=0, sticky="nw", padx=4, pady=2)
        self.payload = tk.Text(top, height=5, width=60)
        self.payload.insert("1.0", "Привет, базовая станция! Это тест шифрования A5.")
        self.payload.grid(row=len(fields), column=1, sticky="ew", padx=4, pady=2)

        ttk.Button(top, text="Run Auth + Secure Send", command=self.run_flow).grid(
            row=len(fields) + 1, column=1, sticky="e", padx=4, pady=8
        )

        ttk.Label(self.root, text="Log").pack(anchor="w", padx=12)
        self.log = tk.Text(self.root, height=16)
        self.log.pack(fill="both", expand=True, padx=10, pady=6)

    def append(self, msg: str):
        self.log.insert("end", msg + "\n")
        self.log.see("end")

    def _send(self, sock: socket.socket, payload: dict):
        sock.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode())

    def _recv(self, sock: socket.socket) -> dict:
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Server disconnected")
            data += chunk
        return json.loads(data.decode().strip())

    def run_flow(self):
        try:
            host = self.host_var.get().strip()
            port = int(self.port_var.get().strip())
            imsi = self.imsi_var.get().strip()
            ki = bytes.fromhex(self.ki_var.get().strip())
            frame = int(self.frame_var.get().strip())
            payload = self.payload.get("1.0", "end").strip().encode()

            with socket.create_connection((host, port), timeout=10) as sock:
                self.append("[MS] Sending auth_request")
                self._send(sock, {"type": "auth_request", "imsi": imsi})

                chall = self._recv(sock)
                self.append(f"[NETWORK] {chall}")
                if chall.get("type") != "auth_challenge":
                    messagebox.showerror("Auth failed", str(chall))
                    return

                rand = bytes.fromhex(chall["rand"])
                sres, kc = a3_a8(ki, rand)
                self.append(f"[MS] Computed SRES={sres.hex()} Kc={kc.hex()}")

                self._send(sock, {"type": "auth_response", "sres": sres.hex()})
                auth = self._recv(sock)
                self.append(f"[NETWORK] {auth}")
                if auth.get("type") != "auth_accept":
                    messagebox.showerror("Auth rejected", str(auth))
                    return

                cipher = a5_encrypt(kc, frame, payload)
                self.append(f"[MS] A5 cipher: {cipher.hex()}")
                self._send(
                    sock,
                    {
                        "type": "secure_data",
                        "frame": frame,
                        "ciphertext": cipher.hex(),
                    },
                )
                ack = self._recv(sock)
                self.append(f"[NETWORK] {ack}")
                messagebox.showinfo("Done", "Authentication + encrypted send complete")
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = GSMClientGUI(root)
    root.mainloop()
