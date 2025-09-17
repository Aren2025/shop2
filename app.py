from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
from datetime import datetime
import os
from functools import wraps

# Cargar variables de entorno
from dotenv import load_dotenv
load_dotenv()

# Configurar Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

app = Flask(__name__)
app.secret_key = "una_clave_super_secreta_y_unica"

# ----------------- Tipo de cambio -----------------
TIPO_CAMBIO = {
    "USD": 1,
    "ARS": 350,
    "CLP": 900,
    "COP": 5000,
    "MXN": 18
}

# ----------------- PRODUCTOS -----------------
PRODUCTOS = {
    "Netflix Completa": 8,
    "Netflix Perfil": 5,
    "Prime Video Completa": 8,
    "Prime Video Perfil": 6,
    "Spotify Individual": 4,
    "HBO Platinum Completa": 10,
    "HBO Platinum Perfil": 8,
    "Disney Completa": 8,
    "Disney Perfil": 6,
    "Crunchyroll Completa": 6,
    "Crunchyroll Perfil": 4,
    "Vix Completa": 5,
    "Vix Perfil": 3,
    "Paramount Completa": 7,
    "Paramount Perfil": 5,
    "HBO Estándar Completa": 8,
    "HBO Estándar Perfil": 6,
    "Apple TV Completa": 6,
    "Apple TV Perfil": 5,
}

# ----------------- Base de datos -----------------
def get_db():
    if os.path.exists("/data"):
        db_path = "/data/usuarios.db"
    else:
        db_path = "usuarios.db"
    conn = sqlite3.connect(db_path, check_same_thread=False)  # ← ¡ESTO ES CLAVE!
    conn.row_factory = sqlite3.Row
    return conn

# Crear tablas
with get_db() as db:
    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        telefono TEXT,
        pais TEXT,
        saldo REAL DEFAULT 0,
        moneda TEXT DEFAULT 'MXN'
    )
    """)
    db.execute("""
    CREATE TABLE IF NOT EXISTS cuentas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        producto TEXT,
        email TEXT,
        password TEXT,
        estado TEXT DEFAULT 'disponible',
        vendido_a INTEGER,
        perfil TEXT DEFAULT 'P1',
        pin TEXT DEFAULT 'No tiene',
        instrucciones TEXT DEFAULT 'No modificar Datos',
        renovable TEXT DEFAULT 'Producto No Renovable',
        dispositivo_limit TEXT DEFAULT 'Solo 1 dispositivo',
        FOREIGN KEY (vendido_a) REFERENCES users(id)
    )
    """)
    db.commit()

# ----------------- Decorador admin -----------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Debes iniciar sesión primero", "error")
            return redirect(url_for("login"))
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not user or user["is_admin"] != 1:
            flash("No tienes permisos para acceder a esta página", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function

# ----------------- Rutas -----------------
@app.route("/")
def index():
    if "user_id" in session:
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

        # calcular stock disponible por producto
        stock = {}
        for prod in PRODUCTOS.keys():
            stock[prod] = db.execute(
                "SELECT COUNT(*) as c FROM cuentas WHERE producto=? AND estado='disponible'",
                (prod,)
            ).fetchone()['c']

        return render_template("index.html",
                               username=session["username"],
                               saldo=user["saldo"],
                               moneda=user["moneda"],
                               productos=PRODUCTOS,
                               stock=stock)
    return render_template("index.html", username=None, productos={})


@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        telefono = request.form["telefono"].strip()
        pais = request.form["pais"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Las contraseñas no coinciden.", "error")
            return redirect(url_for("register"))

        if not username or not email or not password:
            flash("Debes completar todos los campos obligatorios.", "error")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username,email,password,telefono,pais) VALUES (?,?,?,?,?)",
                (username,email,hashed_password,telefono,pais)
            )
            db.commit()
            flash("Usuario creado con éxito.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed: users.username" in str(e):
                flash("El nombre de usuario ya existe.", "error")
            elif "UNIQUE constraint failed: users.email" in str(e):
                flash("El correo ya existe.", "error")
            else:
                flash(f"Error al crear usuario: {e}", "error")
            return redirect(url_for("register"))

    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        email = request.form["email"]
        password = request.form["password"]
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password"],password):
            session["user_id"]=user["id"]
            session["username"]=user["username"]
            flash("Has iniciado sesión.", "success")
            return redirect(url_for("index"))
        else:
            flash("Credenciales inválidas.","error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.","success")
    return redirect(url_for("index"))

# ----------------- Saldo y Stripe -----------------
@app.route("/saldo", methods=["GET"])
def saldo():
    if "user_id" not in session:
        flash("Debes iniciar sesión primero","error")
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
    moneda = user["moneda"]

    PAQUETES = {
        "Pequeño": {"coins": 90, "precio_usd": 5},
        "Mediano": {"coins": 200, "precio_usd": 10},
        "Grande": {"coins": 380, "precio_usd": 20},
    }

    paquetes_locales = {}
    for nombre, paquete in PAQUETES.items():
        precio_local = paquete["precio_usd"] * TIPO_CAMBIO.get(moneda, 1)
        paquetes_locales[nombre] = {
            "coins": paquete["coins"],
            "precio_local": round(precio_local, 2),
            "precio_usd": paquete["precio_usd"]
        }

    from_success = request.args.get('from_success') is not None

    return render_template("saldo.html",
                           saldo=user["saldo"],
                           moneda=moneda,
                           paquetes=paquetes_locales,
                           from_success=from_success)

@app.route("/recargar_tarjeta", methods=["POST"])
def recargar_tarjeta():
    if "user_id" not in session:
        flash("Debes iniciar sesión primero","error")
        return redirect(url_for("login"))

    paquete = request.form["paquete"]
    moneda = request.form["moneda"]
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()

    PAQUETES = {
        "Pequeño": {"coins": 90, "precio_usd": 5},
        "Mediano": {"coins": 200, "precio_usd": 10},
        "Grande": {"coins": 380, "precio_usd": 20},
    }

    if paquete not in PAQUETES:
        flash("Paquete inválido", "error")
        return redirect(url_for("saldo"))

    cantidad_usd = PAQUETES[paquete]["precio_usd"]
    cantidad_local = cantidad_usd * TIPO_CAMBIO.get(moneda, 1)

    try:
        session_stripe = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': moneda.lower(),
                    'product_data': {'name': f'Recarga {paquete} ({PAQUETES[paquete]["coins"]} coins)'},
                    'unit_amount': int(cantidad_local * 100),
                },
                'quantity': 1
            }],
            mode='payment',
            success_url=url_for('saldo_success', _external=True),
            cancel_url=url_for('saldo', _external=True),
            client_reference_id=str(session["user_id"]),
            metadata={"paquete": paquete, "moneda": moneda}
        )
        return redirect(session_stripe.url, code=303)
    except Exception as e:
        flash(f"Error al crear la sesión de pago: {str(e)}", "error")
        return redirect(url_for("saldo"))

@app.route("/saldo_success")
def saldo_success():
    if "user_id" not in session:
        return redirect(url_for("login"))

    flash("¡Pago completado! Tu saldo se actualizará automáticamente en unos segundos.", "success")
    return redirect(url_for("saldo", from_success=1))

@app.route("/api/saldo_actual")
def get_saldo_actual():
    if "user_id" not in session:
        return jsonify({"error": "No autorizado"}), 401

    db = get_db()
    user = db.execute("SELECT saldo FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if user:
        return jsonify({"saldo": user["saldo"]})
    else:
        return jsonify({"error": "Usuario no encontrado"}), 404

# ----------------- Webhook de Stripe -----------------
@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        print("⚠️ Webhook error: Invalid payload")
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        print("⚠️ Webhook error: Invalid signature")
        return "Invalid signature", 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('client_reference_id')

        if not user_id:
            print("⚠️ Webhook: No user_id in session")
            return "No user ID", 400

        paquete = session['metadata'].get('paquete')
        PAQUETES_COINS = {
            "Pequeño": 90,
            "Mediano": 200,
            "Grande": 380,
        }
        coins = PAQUETES_COINS.get(paquete, 0)
        moneda = session['metadata'].get('moneda', 'MXN')

        if coins <= 0:
            print(f"⚠️ Webhook: Invalid package '{paquete}'")
            return "Invalid package", 400

        try:
            db = get_db()
            db.execute("UPDATE users SET saldo = saldo + ?, moneda = ? WHERE id = ?",
                      (coins, moneda, int(user_id)))
            db.commit()
            print(f"✅ Webhook: Acreditado {coins} coins al usuario {user_id}")
        except Exception as e:
            print(f"❌ Webhook DB error: {e}")
            return "DB Error", 500

    return "OK", 200

# ----------------- Compra con asignación de cuentas -----------------
@app.route("/comprar/<producto>", methods=["POST"])
def comprar(producto):
    if "user_id" not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"error": "Debes iniciar sesión primero."}), 401
        return redirect(url_for("login"))

    if producto not in PRODUCTOS:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"error": "Producto inválido."}), 400
        return redirect(url_for("index"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

    precio_usd = PRODUCTOS[producto]
    moneda = user["moneda"]

    if moneda == "MXN":
        precio_local = precio_usd
    else:
        precio_local = round(precio_usd / TIPO_CAMBIO["MXN"] * TIPO_CAMBIO.get(moneda, 1), 2)

    cuenta = db.execute(
        "SELECT * FROM cuentas WHERE producto=? AND estado='disponible' LIMIT 1",
        (producto,)
    ).fetchone()
    if not cuenta:
        msg = f"No hay cuentas disponibles para {producto}"
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"error": msg}), 404
        return redirect(url_for("index"))

    # Marcar como vendida y descontar saldo
    db.execute("UPDATE cuentas SET estado='vendida', vendido_a=? WHERE id=?", (session["user_id"], cuenta["id"]))
    nuevo_saldo = user["saldo"] - precio_local
    db.execute("UPDATE users SET saldo=? WHERE id=?", (nuevo_saldo, session["user_id"]))
    db.commit()

    # Datos adicionales
    perfil = cuenta["perfil"]
    pin = cuenta["pin"]
    instrucciones = cuenta["instrucciones"]
    renovable = cuenta["renovable"]
    dispositivos = cuenta["dispositivo_limit"]

    MESES_ES = {
        1:"enero",2:"febrero",3:"marzo",4:"abril",5:"mayo",6:"junio",
        7:"julio",8:"agosto",9:"septiembre",10:"octubre",11:"noviembre",12:"diciembre"
    }
    hoy = datetime.now()
    fecha_compra = f"{hoy.day}/{MESES_ES[hoy.month]}/{hoy.year}"

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            "producto": producto,
            "renovable": renovable,
            "email": cuenta["email"],
            "password": cuenta["password"],
            "perfil": perfil,
            "pin": pin,
            "instrucciones": instrucciones,
            "dispositivo_limit": dispositivos,
            "precio": round(precio_local, 2),
            "moneda": moneda,
            "saldo": round(nuevo_saldo, 2),
            "fecha_compra": fecha_compra
        })

    return redirect(url_for("index"))

@app.route("/perfil")
def perfil():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
    cuentas = db.execute("SELECT * FROM cuentas WHERE vendido_a=?",(session["user_id"],)).fetchall()
    return render_template("perfil.html", user=user, cuentas=cuentas)

# ----------------- PANEL ADMIN -----------------
@app.route("/admin")
@admin_required
def admin_panel():
    db = get_db()
    cuentas = db.execute("SELECT * FROM cuentas").fetchall()
    productos = PRODUCTOS
    return render_template("admin_panel.html", cuentas=cuentas, productos=productos)

@app.route("/admin/agregar_cuenta", methods=["POST"])
@admin_required
def admin_agregar_cuenta():
    producto = request.form["producto"]
    email = request.form["email"]
    password = request.form["password"]
    perfil = request.form.get("perfil", "P1")
    pin = request.form.get("pin", "No tiene")
    instrucciones = request.form.get("instrucciones", "No modificar Datos")
    renovable = request.form.get("renovable", "Producto No Renovable")
    dispositivo_limit = request.form.get("dispositivo_limit", "Solo 1 dispositivo")

    db = get_db()
    db.execute("""
        INSERT INTO cuentas (producto,email,password,perfil,pin,instrucciones,renovable,dispositivo_limit)
        VALUES (?,?,?,?,?,?,?,?)
    """, (producto,email,password,perfil,pin,instrucciones,renovable,dispositivo_limit))
    db.commit()
    flash("Cuenta agregada correctamente", "success")
    return redirect(url_for("admin_panel"))

# ----------------- PANEL DE ADMIN: MODIFICAR PRECIOS EN MXN -----------------
@app.route("/admin/precios", methods=["GET", "POST"])
@admin_required
def admin_precios():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if not user or not user["is_admin"]:
        flash("No tienes permisos para acceder a esta página.", "error")
        return redirect(url_for("index"))

    precios_mxn = {prod: float(precio) for prod, precio in PRODUCTOS.items()}

    if request.method == "POST":
        for producto in PRODUCTOS.keys():
            nuevo_precio = request.form.get(producto)
            if nuevo_precio:
                try:
                    PRODUCTOS[producto] = float(nuevo_precio)
                except ValueError:
                    flash(f"Precio inválido para {producto}", "error")
        flash("Precios actualizados correctamente.", "success")
        return redirect(url_for("admin_precios"))

    return render_template("admin_precios.html", productos=precios_mxn)

# ----------------- Iniciar app -----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

