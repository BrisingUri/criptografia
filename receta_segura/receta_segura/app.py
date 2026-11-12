"""Receta Segura - servidor web (Flask). Ejecutar:  python app.py"""
import os
import secrets
import time
from functools import wraps

from flask import Flask, jsonify, request, send_file, send_from_directory, session
import io

import core

core.init_secrets()
core.init_db()

app = Flask(__name__, static_folder="static")
app.secret_key = os.environ["RECETAS_FLASK_SECRET"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  MAX_CONTENT_LENGTH=5 * 1024 * 1024)
@app.after_request
def no_cache(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp
DEMO = os.environ.get("RECETAS_DEMO", "1") == "1"
SESSION_TTL = 30 * 60
SESSIONS = {}   # sid -> {doctor, priv, exp}. La llave privada descifrada vive SOLO en memoria.


def current():
    s = SESSIONS.get(session.get("sid"))
    if not s or s["exp"] < time.time():
        SESSIONS.pop(session.get("sid"), None)
        return None
    s["exp"] = time.time() + SESSION_TTL
    return s


def auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        s = current()
        if not s:
            return jsonify(error="Sesión no iniciada o expirada."), 401
        return fn(s, *a, **kw)
    return wrapper


def demo_only(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not DEMO:
            return jsonify(error="Modo demostración desactivado."), 403
        return fn(*a, **kw)
    return wrapper


@app.errorhandler(ValueError)
def bad_value(e):
    return jsonify(error=str(e)), 400


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.post("/api/register")
def register():
    d = request.get_json(force=True, silent=True) or {}
    core.register_doctor(d.get("username"), d.get("password"), d.get("nombre"), d.get("cedula"))
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    d = request.get_json(force=True, silent=True) or {}
    try:
        doctor, priv = core.login_doctor(d.get("username"), d.get("password"))
    except PermissionError as e:
        return jsonify(error=str(e)), 401
    sid = secrets.token_urlsafe(32)
    SESSIONS[sid] = {"doctor": doctor, "priv": priv, "exp": time.time() + SESSION_TTL}
    session["sid"] = sid
    return jsonify(doctor=doctor, demo=DEMO)


@app.post("/api/logout")
def logout():
    SESSIONS.pop(session.pop("sid", None), None)
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    s = current()
    return jsonify(doctor=s["doctor"] if s else None, demo=DEMO)


@app.get("/api/recetas")
@auth
def list_recetas(s):
    return jsonify(core.list_prescriptions(s["doctor"]["id"]))


@app.post("/api/recetas")
@auth
def create_receta(s):
    data = request.get_json(force=True, silent=True) or {}
    return jsonify(core.create_prescription(s["doctor"], s["priv"], data))


@app.get("/api/recetas/<folio>/pdf")
@auth
def download_pdf(s, folio):
    if not core.get_owned(folio, s["doctor"]["id"]):
        return jsonify(error="Receta no encontrada."), 404
    return send_file(core.pdf_path(folio), mimetype="application/pdf", as_attachment=True,
                     download_name=f"{folio}.pdf")


@app.post("/api/verificar")
def verificar():
    """Publico: lo usa la farmacia / paciente. Acepta PDF y/o folio."""
    f = request.files.get("pdf")
    pdf = f.read() if f and f.filename else None
    folio = (request.form.get("folio") or "").strip()
    if not pdf and not folio:
        return jsonify(error="Adjunta el PDF de la receta o escribe su folio."), 400
    return jsonify(core.verify(pdf=pdf, folio=folio or None))


@app.get("/api/demo/pdf-alterado/<folio>")
@auth
@demo_only
def demo_pdf(s, folio):
    if not core.get_owned(folio, s["doctor"]["id"]):
        return jsonify(error="Receta no encontrada."), 404
    return send_file(io.BytesIO(core.demo_tampered_pdf(folio)), mimetype="application/pdf",
                     as_attachment=True, download_name=f"{folio}_ALTERADO.pdf")


@app.post("/api/demo/alterar-bd/<folio>")
@auth
@demo_only
def demo_db(s, folio):
    if not core.get_owned(folio, s["doctor"]["id"]):
        return jsonify(error="Receta no encontrada."), 404
    core.demo_tamper_db(folio)
    return jsonify(ok=True)


if __name__ == "__main__":
    import threading
    import webbrowser
    threading.Timer(1.0, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
    app.run(host="127.0.0.1", port=5000, debug=False)
