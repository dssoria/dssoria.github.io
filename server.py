import json
import os
import secrets
import sqlite3
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "registros.db"
PORT = int(os.getenv("PORT", "3000"))
USERNAME = os.getenv("APP_USERNAME", "admin")
PASSWORD = os.getenv("APP_PASSWORD", "admin123")

sessions = {}


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS registros (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT NOT NULL,
            monto REAL NOT NULL,
            categoria TEXT NOT NULL,
            destino TEXT NOT NULL,
            detalle TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def get_session_id(headers):
    cookie = headers.get("Cookie")
    if not cookie:
        return None
    parsed = SimpleCookie()
    parsed.load(cookie)
    morsel = parsed.get("session_id")
    return morsel.value if morsel else None


class RequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return None

    def _send_json(self, data, status=HTTPStatus.OK, extra_headers=None):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def _is_authenticated(self):
        session_id = get_session_id(self.headers)
        return bool(session_id and sessions.get(session_id))

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/session":
            return self._send_json({"authenticated": self._is_authenticated()})

        if path == "/api/registros":
            if not self._is_authenticated():
                return self._send_json({"message": "No autenticado"}, status=HTTPStatus.UNAUTHORIZED)

            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute(
                "SELECT id, fecha, monto, categoria, destino, detalle FROM registros ORDER BY fecha DESC, id DESC"
            ).fetchall()
            conn.close()
            data = [
                {
                    "id": row[0],
                    "fecha": row[1],
                    "monto": row[2],
                    "categoria": row[3],
                    "destino": row[4],
                    "detalle": row[5],
                }
                for row in rows
            ]
            return self._send_json(data)

        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/login":
            data = self._read_json()
            if not data:
                return self._send_json({"message": "JSON inválido"}, status=HTTPStatus.BAD_REQUEST)

            if data.get("username") == USERNAME and data.get("password") == PASSWORD:
                session_id = secrets.token_hex(16)
                sessions[session_id] = True
                headers = {"Set-Cookie": f"session_id={session_id}; HttpOnly; SameSite=Lax; Path=/"}
                return self._send_json({"message": "Autenticación exitosa"}, extra_headers=headers)

            return self._send_json({"message": "Credenciales inválidas"}, status=HTTPStatus.UNAUTHORIZED)

        if path == "/api/logout":
            session_id = get_session_id(self.headers)
            if session_id:
                sessions.pop(session_id, None)
            headers = {"Set-Cookie": "session_id=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"}
            return self._send_json({"message": "Sesión cerrada"}, extra_headers=headers)

        if path == "/api/registros":
            if not self._is_authenticated():
                return self._send_json({"message": "No autenticado"}, status=HTTPStatus.UNAUTHORIZED)

            data = self._read_json()
            if not data:
                return self._send_json({"message": "JSON inválido"}, status=HTTPStatus.BAD_REQUEST)

            required = ["fecha", "monto", "categoria", "destino", "detalle"]
            if any(not str(data.get(field, "")).strip() for field in required if field != "monto"):
                return self._send_json({"message": "Todos los campos son obligatorios"}, status=HTTPStatus.BAD_REQUEST)

            try:
                monto = float(data.get("monto"))
            except (TypeError, ValueError):
                return self._send_json({"message": "Monto inválido"}, status=HTTPStatus.BAD_REQUEST)

            conn = sqlite3.connect(DB_PATH)
            cursor = conn.execute(
                "INSERT INTO registros (fecha, monto, categoria, destino, detalle) VALUES (?, ?, ?, ?, ?)",
                [data["fecha"], monto, data["categoria"].strip(), data["destino"].strip(), data["detalle"].strip()],
            )
            conn.commit()
            last_id = cursor.lastrowid
            conn.close()

            return self._send_json(
                {
                    "id": last_id,
                    "fecha": data["fecha"],
                    "monto": monto,
                    "categoria": data["categoria"].strip(),
                    "destino": data["destino"].strip(),
                    "detalle": data["detalle"].strip(),
                },
                status=HTTPStatus.CREATED,
            )

        return self._send_json({"message": "Ruta no encontrada"}, status=HTTPStatus.NOT_FOUND)


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), RequestHandler)
    print(f"Servidor iniciado en http://localhost:{PORT}")
    server.serve_forever()
