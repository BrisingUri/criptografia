"""
Receta Segura - nucleo criptografico y de datos.

MECANISMO 1 (simetrico)  : AES-256-GCM cifra el contenido completo de cada receta en la BD.
MECANISMO 2 (asimetrico) : Ed25519; cada medico firma  folio + hash(contenido) + hash(PDF).
Hash                     : SHA-256 (contenido canonico de la receta y bytes del PDF final).

Manejo de llaves (nada hardcodeado):
  - Llave AES-256  -> variable de entorno RECETAS_AES_KEY (o data/.env, creado solo la primera vez).
  - Llave privada Ed25519 de cada medico -> se guarda CIFRADA con la contrasena del medico
    (PKCS8 + BestAvailableEncryption). Solo se descifra en memoria al iniciar sesion.
  - Llave publica Ed25519 -> en la BD; sirve para que cualquiera verifique las firmas.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
from contextlib import closing
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import pdfgen

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("RECETAS_DATA", BASE / "data"))
PDF_DIR = DATA / "pdfs"
DB_PATH = DATA / "recetas.db"
ENV_PATH = DATA / ".env"
FOLIO_RE = re.compile(r"RX-\d{8}-[0-9A-F]{6}")


# ----------------------------------------------------------------- utilidades
def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def canonical_json(obj) -> bytes:
    """Serializacion determinista: mismo contenido -> mismos bytes -> mismo hash."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ------------------------------------------------------------------- secretos
def init_secrets():
    """Carga llaves desde el entorno; si no existen, las genera una vez y las guarda en data/.env"""
    DATA.mkdir(exist_ok=True)
    PDF_DIR.mkdir(exist_ok=True)
    existing = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                existing[k.strip()] = v.strip()
    generators = {
        "RECETAS_AES_KEY": lambda: b64e(AESGCM.generate_key(bit_length=256)),
        "RECETAS_FLASK_SECRET": lambda: secrets.token_hex(32),
    }
    changed = False
    for var, gen in generators.items():
        if var in os.environ:          # el entorno real tiene prioridad
            continue
        if var not in existing:
            existing[var] = gen()
            changed = True
        os.environ[var] = existing[var]
    if changed:
        ENV_PATH.write_text("".join(f"{k}={v}\n" for k, v in existing.items()))
        try:
            os.chmod(ENV_PATH, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


def aes_key() -> bytes:
    key = b64d(os.environ["RECETAS_AES_KEY"])
    if len(key) != 32:
        raise RuntimeError("RECETAS_AES_KEY debe ser de 32 bytes (AES-256) en base64.")
    return key


# ------------------------------------------------------------------------- BD
def _con():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def q(sql, args=(), one=False):
    with closing(_con()) as con:
        cur = con.execute(sql, args)
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def ex(sql, args=()):
    with closing(_con()) as con:
        with con:
            con.execute(sql, args)


def init_db():
    with closing(_con()) as con:
        with con:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS doctors(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL, nombre TEXT NOT NULL, cedula TEXT NOT NULL,
                salt TEXT NOT NULL, pwd_hash TEXT NOT NULL,
                public_pem TEXT NOT NULL, private_pem_enc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS prescriptions(
                folio TEXT PRIMARY KEY, doctor_id INTEGER NOT NULL, fecha TEXT NOT NULL,
                data_enc TEXT NOT NULL, content_hash TEXT NOT NULL,
                pdf_hash TEXT NOT NULL, signature TEXT NOT NULL);
            """)


# -------------------------------------------------------------------- medicos
def _hash_pwd(pwd: str, salt: bytes) -> str:
    return b64e(hashlib.scrypt(pwd.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32))


def register_doctor(username, password, nombre, cedula):
    username, nombre, cedula = (username or "").strip().lower(), (nombre or "").strip(), (cedula or "").strip()
    if not re.fullmatch(r"[a-z0-9_.-]{3,30}", username):
        raise ValueError("Usuario: de 3 a 30 caracteres (letras, números, . _ -).")
    if not nombre or not cedula:
        raise ValueError("Nombre y cédula profesional son obligatorios.")
    if len(password or "") < 8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres.")
    priv = Ed25519PrivateKey.generate()
    private_pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode()))      # cifrada con la contraseña
    public_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    salt = os.urandom(16)
    try:
        ex("INSERT INTO doctors(username,nombre,cedula,salt,pwd_hash,public_pem,private_pem_enc) VALUES(?,?,?,?,?,?,?)",
           (username, nombre, cedula, b64e(salt), _hash_pwd(password, salt),
            public_pem.decode(), private_pem.decode()))
    except sqlite3.IntegrityError:
        raise ValueError("Ese usuario ya existe.")


def login_doctor(username, password):
    """Devuelve (datos_del_medico, llave_privada_descifrada) o lanza PermissionError."""
    row = q("SELECT * FROM doctors WHERE username=?", ((username or "").strip().lower(),), one=True)
    salt = b64d(row["salt"]) if row else os.urandom(16)
    h = _hash_pwd(password or "", salt)
    if not row or not hmac.compare_digest(h, row["pwd_hash"]):
        raise PermissionError("Usuario o contraseña incorrectos.")
    priv = serialization.load_pem_private_key(row["private_pem_enc"].encode(), password=password.encode())
    return {"id": row["id"], "username": row["username"], "nombre": row["nombre"], "cedula": row["cedula"]}, priv


# ------------------------------------------------------------ cifrado simetrico
def encrypt_record(canonical: bytes, folio: str) -> str:
    nonce = os.urandom(12)                                   # nonce unico por cifrado
    ct = AESGCM(aes_key()).encrypt(nonce, canonical, folio.encode())   # AAD = folio
    return b64e(nonce + ct)


def decrypt_record(blob: str, folio: str) -> bytes:
    raw = b64d(blob)
    return AESGCM(aes_key()).decrypt(raw[:12], raw[12:], folio.encode())


# ----------------------------------------------------------------------- firma
def signed_message(folio, content_hash, pdf_hash, doctor_id) -> bytes:
    return f"RX1|{folio}|{content_hash}|{pdf_hash}|{doctor_id}".encode()


def _clean(s, maxlen):
    s = str(s or "").strip()[:maxlen]
    return s.encode("cp1252", "replace").decode("cp1252")   # el PDF usa Helvetica (Latin-1)


# ---------------------------------------------------------------------- recetas
def create_prescription(doctor: dict, priv, data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Datos inválidos.")
    paciente = _clean(data.get("paciente"), 120)
    if not paciente:
        raise ValueError("El nombre del paciente es obligatorio.")
    meds = []
    for m in (data.get("medicamentos") or [])[:15]:
        nombre = _clean(m.get("nombre"), 150)
        if nombre:
            meds.append({"nombre": nombre, "dosis": _clean(m.get("dosis"), 100),
                         "indicaciones": _clean(m.get("indicaciones"), 300)})
    if not meds:
        raise ValueError("Agrega al menos un medicamento.")

    folio = f"RX-{datetime.now():%Y%m%d}-{secrets.token_hex(3).upper()}"
    record = {
        "folio": folio,
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "medico": {"nombre": doctor["nombre"], "cedula": doctor["cedula"]},
        "paciente": {"nombre": paciente, "edad": _clean(data.get("edad"), 10)},
        "diagnostico": _clean(data.get("diagnostico"), 500),
        "medicamentos": meds,
        "observaciones": _clean(data.get("observaciones"), 1000),
    }
    canonical = canonical_json(record)
    content_hash = sha256_hex(canonical)                      # HASH 1: contenido
    data_enc = encrypt_record(canonical, folio)               # MECANISMO 1: AES-256-GCM
    pdf = pdfgen.build_pdf(record, content_hash)
    pdf_hash = sha256_hex(pdf)                                # HASH 2: archivo PDF final
    signature = b64e(priv.sign(signed_message(folio, content_hash, pdf_hash, doctor["id"])))  # MECANISMO 2

    (PDF_DIR / f"{folio}.pdf").write_bytes(pdf)
    ex("INSERT INTO prescriptions VALUES(?,?,?,?,?,?,?)",
       (folio, doctor["id"], record["fecha"], data_enc, content_hash, pdf_hash, signature))
    return {"folio": folio, "fecha": record["fecha"], "content_hash": content_hash, "pdf_hash": pdf_hash}


def get_owned(folio: str, doctor_id: int):
    if not FOLIO_RE.fullmatch(folio or ""):
        return None
    return q("SELECT * FROM prescriptions WHERE folio=? AND doctor_id=?", (folio, doctor_id), one=True)


def list_prescriptions(doctor_id: int):
    out = []
    for r in q("SELECT * FROM prescriptions WHERE doctor_id=? ORDER BY fecha DESC", (doctor_id,)):
        try:
            paciente = json.loads(decrypt_record(r["data_enc"], r["folio"]))["paciente"]["nombre"]
        except Exception:
            paciente = "⚠ registro ilegible (alterado)"
        out.append({"folio": r["folio"], "fecha": r["fecha"], "paciente": paciente})
    return out


def pdf_path(folio: str) -> Path:
    return PDF_DIR / f"{folio}.pdf"


# ----------------------------------------------------------------- verificacion
def _extract_folio(pdf: bytes):
    m = FOLIO_RE.search(pdf.decode("latin-1", "ignore"))
    return m.group(0) if m else None


def verify(pdf: bytes = None, folio: str = None) -> dict:
    """
    Verifica una receta con tres comprobaciones encadenadas (los textos estan escritos para el medico):
      1) El PDF recibido es identico al emitido (SHA-256 del archivo)
      2) El registro guardado se puede descifrar (AES-256-GCM) y su contenido coincide con el hash emitido
      3) La firma Ed25519 del medico es valida con su llave publica
    """
    res = {"verdict": "NO_RECONOCIDA", "folio": None, "alcance": "pdf" if pdf else "registro",
           "resumen": "Este documento no corresponde a ninguna receta emitida en el sistema.",
           "checks": [], "hashes": {}, "record": None, "medico": None}
    pdf_hash = sha256_hex(pdf) if pdf else None
    row = None
    if pdf:
        row = q("SELECT * FROM prescriptions WHERE pdf_hash=?", (pdf_hash,), one=True)
        if not row:                                   # el PDF no coincide con ninguno: se alteró?
            f = _extract_folio(pdf)
            if f:
                row = q("SELECT * FROM prescriptions WHERE folio=?", (f,), one=True)
    if not row and folio and FOLIO_RE.fullmatch(folio.strip().upper()):
        row = q("SELECT * FROM prescriptions WHERE folio=?", (folio.strip().upper(),), one=True)
    if pdf:
        res["hashes"]["pdf_recibido"] = pdf_hash
    if not row:
        res["checks"].append({"ok": False, "titulo": "La receta está registrada en el sistema",
                              "detalle": "Este documento no corresponde a ninguna receta emitida en el sistema, "
                                         "y tampoco se encontró un folio válido."})
        return res

    res["folio"] = row["folio"]
    res["hashes"]["pdf_emitido"] = row["pdf_hash"]
    checks = res["checks"]

    # 1) el documento PDF es el original
    pdf_fail = False
    if pdf:
        ok = hmac.compare_digest(pdf_hash, row["pdf_hash"])
        pdf_fail = not ok
        checks.append({"ok": ok, "titulo": "El documento es el original",
                       "detalle": "El archivo PDF es exactamente el que se generó al emitir la receta; no ha sido modificado."
                                  if ok else
                                  "El archivo PDF no es el original: fue modificado después de emitirse "
                                  "(por ejemplo, alguien pudo cambiar una dosis o un dato)."})
    else:
        checks.append({"ok": None, "titulo": "El documento es el original",
                       "detalle": "No se adjuntó el PDF, así que solo se revisó el registro guardado en el sistema."})

    # 2) los datos guardados estan intactos y coinciden con lo emitido
    canonical = None
    data_fail = False
    try:
        canonical = decrypt_record(row["data_enc"], row["folio"])
        checks.append({"ok": True, "titulo": "Los datos guardados en el sistema están intactos",
                       "detalle": "El registro de la receta no ha sido manipulado."})
    except InvalidTag:
        data_fail = True
        checks.append({"ok": False, "titulo": "Los datos guardados en el sistema están intactos",
                       "detalle": "El registro de esta receta en el sistema fue manipulado o está dañado, "
                                  "por lo que no es confiable."})
    if canonical is not None:
        recomputed = sha256_hex(canonical)
        res["hashes"]["contenido_recalculado"] = recomputed
        ok = hmac.compare_digest(recomputed, row["content_hash"])
        data_fail = data_fail or not ok
        checks.append({"ok": ok, "titulo": "El contenido es el mismo que registró el médico",
                       "detalle": "Paciente, medicamentos y dosis son exactamente los que el médico indicó al emitir la receta."
                                  if ok else
                                  "El contenido no coincide con lo que el médico registró al emitir la receta."})
        res["record"] = json.loads(canonical)
    else:
        checks.append({"ok": False, "titulo": "El contenido es el mismo que registró el médico",
                       "detalle": "No se pudo comprobar porque los datos guardados están dañados."})
    res["hashes"]["contenido_emitido"] = row["content_hash"]

    # 3) firma del medico
    sig_fail = False
    doc = q("SELECT * FROM doctors WHERE id=?", (row["doctor_id"],), one=True)
    res["medico"] = {"nombre": doc["nombre"], "cedula": doc["cedula"]}
    try:
        pub = serialization.load_pem_public_key(doc["public_pem"].encode())
        pub.verify(b64d(row["signature"]),
                   signed_message(row["folio"], row["content_hash"], row["pdf_hash"], row["doctor_id"]))
        checks.append({"ok": True, "titulo": "La receta fue firmada por el médico",
                       "detalle": f"Lleva la firma digital de {doc['nombre']} (cédula {doc['cedula']}), "
                                  "lo que confirma que fue emitida por este médico."})
    except (InvalidSignature, ValueError):
        sig_fail = True
        checks.append({"ok": False, "titulo": "La receta fue firmada por el médico",
                       "detalle": "La firma del médico no corresponde a esta receta: "
                                  "no se puede confirmar que haya sido emitida por este médico."})

    nombre = doc["nombre"]
    if not (pdf_fail or data_fail or sig_fail):
        res["verdict"] = "VALIDA"
        res["resumen"] = (f"Esta receta es auténtica: es exactamente la que emitió {nombre} y nadie la ha modificado."
                          if pdf else
                          f"Esta receta está registrada y firmada por {nombre}, y su contenido no ha sido modificado.")
    else:
        res["verdict"] = "ALTERADA"
        if pdf_fail and not data_fail and not sig_fail:
            res["resumen"] = ("El documento que presentas fue modificado después de emitirse. "
                              "Lo que el médico registró originalmente está intacto: compáralo con los datos "
                              "originales que aparecen abajo. No debe dispensarse.")
        elif data_fail:
            res["resumen"] = ("El registro de esta receta en el sistema fue manipulado, "
                              "por lo que no se puede confiar en su contenido. No debe dispensarse.")
        else:
            res["resumen"] = "No se puede confirmar que esta receta haya sido emitida por el médico. No debe dispensarse."
    return res

# ------------------------------------------- utilidades SOLO para la demostración
def demo_tampered_pdf(folio: str) -> bytes:
    """Copia del PDF con una dosis cambiada (simula a alguien editando la receta)."""
    data = pdf_path(folio).read_bytes()
    m = re.search(rb"(\d+)(\s?mg)", data)
    if m:
        d = m.group(1)
        new = (b"9" if d[:1] != b"9" else b"1") + d[1:]
        return data[:m.start(1)] + new + data[m.end(1):]
    return data + b"\n%alterado\n"


def demo_tamper_db(folio: str):
    """Corrompe un byte del registro cifrado en la BD (simula un ataque a la base de datos)."""
    row = q("SELECT data_enc FROM prescriptions WHERE folio=?", (folio,), one=True)
    raw = bytearray(b64d(row["data_enc"]))
    raw[20] ^= 0x01
    ex("UPDATE prescriptions SET data_enc=? WHERE folio=?", (b64e(bytes(raw)), folio))
