import csv
import sqlite3

DB_NAME = "usuarios.db"
CSV_FILE = "cuentas.csv"

# Abrir conexión a la base de datos
conn = sqlite3.connect(DB_NAME)
cursor = conn.cursor()

# Asegurar que la tabla tenga las columnas extra
cursor.execute("PRAGMA table_info(cuentas)")
cols = [c[1] for c in cursor.fetchall()]

# Si no existen las columnas extra, agregarlas
extras = {
    "perfil": "TEXT",
    "pin": "TEXT",
    "instrucciones": "TEXT",
    "renovable": "TEXT",
    "dispositivo_limit": "TEXT"
}
for col, tipo in extras.items():
    if col not in cols:
        cursor.execute(f"ALTER TABLE cuentas ADD COLUMN {col} {tipo}")

# Leer el CSV e insertar cuentas
with open(CSV_FILE, newline='', encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        cursor.execute("""
            INSERT INTO cuentas (producto,email,password,perfil,pin,instrucciones,renovable,dispositivo_limit)
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            row["producto"],
            row["email"],
            row["password"],
            row.get("perfil"),
            row.get("pin"),
            row.get("instrucciones"),
            row.get("renovable"),
            row.get("dispositivo_limit")
        ))

conn.commit()
conn.close()

print("✅ Cuentas importadas correctamente desde CSV.")
