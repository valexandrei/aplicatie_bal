import os
import secrets
import smtplib
from email.mime.text import MIMEText
from functools import wraps

import oracledb
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

# INCARCARE CHESTII NECESARE
load_dotenv()
app = Flask(__name__)

# CONFIGURARE SESIUNE (securitate)
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Lipsește SECRET_KEY din .env")

app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,  # JS nu poate citi cookie-ul
    SESSION_COOKIE_SAMESITE="Lax",  # protecție de bază împotriva CSRF
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE") == "1",  # pune COOKIE_SECURE=1 în .env când ai HTTPS
    SEND_FILE_MAX_AGE_DEFAULT=0  # Cache busting
)

# CONFIGURARE BAZĂ DE DATE ORACLE

DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_DSN = os.getenv("DB_DSN")
pool = oracledb.create_pool(user=DB_USER, password=DB_PASS, dsn=DB_DSN, min=2, max=5, increment=1)

# CONFIGURARE EMAIL

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")


def trimitere_email_generic(subiect, mesaj, destinatar):
    msg = MIMEText(mesaj)
    msg['Subject'] = subiect
    msg['From'] = f"Balul FMI <{EMAIL_SENDER}>"
    msg['To'] = destinatar

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Eroare SMTP (Tranzactie): {e}")
        return False


def trimite_email_verificare(destinatar, cod):
    subiect = "Verificare cont - Balul Bobocilor FMI"
    mesaj = f"Salut,\n\nCodul tău de verificare este: {cod}\n\nTe rugăm să introduci acest cod în aplicație pentru a-ți activa contul și a putea cumpăra bilete."

    return trimitere_email_generic(subiect, mesaj, destinatar)


def trimite_email_bilet(destinatar, cod_tranzactie, nr_bilete):
    subiect = "Biletele tale - Balul Bobocilor FMI"
    mesaj = f"Salut,\n\nTranzacția ta a fost înregistrată cu succes!\nAi achiziționat {nr_bilete} bilet(e).\n\nCodul tău de acces (UUID-ul) este:\n{cod_tranzactie}\n\nTe rugăm să prezinți acest cod la intrare (poți să îl salvezi sau să arăți acest email).\n\nDistracție plăcută,\nEchipa Balul FMI"

    return trimitere_email_generic(subiect, mesaj, destinatar)


# AUTENTIFICARE / AUTORIZARE

def get_current_user():
    """Returnează utilizatorul din sesiune, citit PROASPĂT din DB (sau None).
    Rolul de admin nu se ia niciodată de la client."""
    uid = session.get("user_id")
    if not uid:
        return None

    with pool.acquire() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id_utilizator, nume, email, este_admin, cont_verificat "
                "FROM utilizator WHERE id_utilizator = :id", id=uid)
            row = cursor.fetchone()

    if not row:
        session.clear()
        return None

    return {
        "id": row[0],
        "nume": row[1],
        "email": row[2],
        "este_admin": row[3],
        "cont_verificat": row[4],
    }


def is_admin(user):
    return bool(user) and user["este_admin"] == 1 and user["cont_verificat"] == 1


def admin_required(f):
    """Pentru rutele /api/admin/*: 401 dacă nu e logat, 403 dacă nu e admin."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"eroare": "Neautentificat"}), 401
        if not is_admin(user):
            return jsonify({"eroare": "Acces interzis"}), 403
        return f(*args, **kwargs)

    return wrapper


# RUTE AFIȘARE PAGINI HTML

@app.route('/')
def home(): return render_template('index.html')


@app.route('/signin')
def signin(): return render_template('signin.html')


@app.route('/signup')
def signup(): return render_template('signup.html')


@app.route('/verify')
def verify(): return render_template('verify.html')


@app.route('/bilete')
def bilete():
    # Redirecționare din backend dacă utilizatorul nu e logat
    user = get_current_user()
    if not user:
        return redirect(url_for('signin'))

    # Dacă este logat, îi trimitem datele profilului în șablonul HTML
    return render_template('bilete.html', user=user)


@app.route('/admin')
def admin():
    # Pagina de admin nu se servește deloc celor fără drepturi
    if not is_admin(get_current_user()):
        return redirect('/')
    return render_template('admin.html')


# RUTE API - CONT

@app.route('/api/register', methods=['POST'])
def api_register():
    date = request.get_json(silent=True) or {}
    nume = (date.get('nume') or '').strip()
    email = (date.get('email') or '').strip()
    parola_raw = date.get('parola') or ''

    if not nume or not email or '@' not in email:
        return jsonify({"eroare": "Completează numele și un email valid."}), 400
    if len(parola_raw) < 8:
        return jsonify({"eroare": "Parola trebuie să aibă minim 8 caractere."}), 400

    parola_hash = generate_password_hash(parola_raw)
    cod_generat = str(secrets.randbelow(900000) + 100000)

    with pool.acquire() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id_utilizator FROM utilizator WHERE email = :email", email=email)
            if cursor.fetchone():
                return jsonify({"eroare": "Acest email este deja folosit"}), 409

            try:
                sql = '''INSERT INTO utilizator (nume, email, parola, este_admin, cont_verificat, cod_verificare)
                         VALUES (:nume, :email, :parola_hash, 0, 0, :cod)'''
                cursor.execute(sql, nume=nume, email=email, parola_hash=parola_hash, cod=cod_generat)
                connection.commit()
            except oracledb.IntegrityError:
                return jsonify({"eroare": "Acest email este deja folosit"}), 409

    # Pagina /verify știe pentru ce email se introduce codul
    session['pending_email'] = email

    succes = trimite_email_verificare(email, cod_generat)
    if not succes:
        return jsonify({"mesaj": "Cont creat, dar email-ul cu codul nu a putut fi trimis."}), 201

    return jsonify({"mesaj": "Cont creat. Verifică-ți email-ul pentru cod!"}), 201


@app.route('/api/verify-email', methods=['POST'])
def api_verify_email():
    date = request.get_json(silent=True) or {}
    email = (date.get('email') or session.get('pending_email') or '').strip()
    cod_introdus = str(date.get('cod') or '').strip()

    if not email or not cod_introdus:
        return jsonify({"eroare": "Email și cod necesare."}), 400

    with pool.acquire() as connection:
        with connection.cursor() as cursor:
            sql = "SELECT id_utilizator FROM utilizator WHERE email = :email AND cod_verificare = :cod"
            cursor.execute(sql, email=email, cod=cod_introdus)
            user_row = cursor.fetchone()

            if user_row:
                id_user = user_row[0]
                cursor.execute(
                    "UPDATE utilizator SET cont_verificat = 1, cod_verificare = NULL WHERE id_utilizator = :id",
                    id=id_user)
                connection.commit()
                session.pop('pending_email', None)
                return jsonify({"mesaj": "Cont validat cu succes!"}), 200
            else:
                return jsonify({"eroare": "Cod incorect sau cont deja validat!"}), 400


@app.route('/api/login', methods=['POST'])
def api_login():
    date = request.get_json(silent=True) or {}
    email = (date.get('email') or '').strip()
    parola_raw = date.get('parola') or ''

    with pool.acquire() as connection:
        with connection.cursor() as cursor:
            sql = "SELECT id_utilizator, email, este_admin, parola, cont_verificat FROM utilizator WHERE email = :email"
            cursor.execute(sql, email=email)
            user_row = cursor.fetchone()

    if not (user_row and check_password_hash(user_row[3], parola_raw)):
        return jsonify({"eroare": "Email sau parolă incorecte"}), 401

    # Cont neverificat: NU se creează sesiune de login, doar se permite pasul /verify
    if user_row[4] != 1:
        session.clear()
        session['pending_email'] = user_row[1]
        return jsonify({"eroare": "Contul nu este verificat.", "necesita_verificare": True}), 403

    session.clear()  # previne session fixation
    session['user_id'] = user_row[0]

    user_data = {
        "id": user_row[0],
        "email": user_row[1],
        "este_admin": user_row[2],
        "cont_verificat": user_row[4]
    }
    return jsonify({"user": user_data}), 200


@app.route('/api/me', methods=['GET'])
def api_me():
    user = get_current_user()
    if not user:
        return jsonify({"eroare": "Neautentificat"}), 401
    return jsonify({"user": user}), 200


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({"mesaj": "Delogat"}), 200


# RUTE API - ADMIN (toate protejate cu @admin_required)

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def api_admin_users():
    search_query = request.args.get('q', '').lower()

    with pool.acquire() as connection:
        with connection.cursor() as cursor:
            sql = 'SELECT id_utilizator, nume, email, este_admin, cont_verificat FROM utilizator WHERE LOWER(email) LIKE :q OR TO_CHAR(id_utilizator) = :id_exact'
            cursor.execute(sql, q=f"%{search_query}%", id_exact=search_query)

            nume_coloane = [col[0].lower() for col in cursor.description]
            cursor.rowfactory = lambda *args: dict(zip(nume_coloane, args))

            rezultate = cursor.fetchall()
            return jsonify(rezultate), 200


@app.route('/api/admin/transactions', methods=['GET'])
@admin_required
def api_admin_transactions():
    search_query = request.args.get('q', '').lower()
    # Eliminăm cratimele pentru siguranță
    clean_uuid_query = search_query.replace('-', '')

    with pool.acquire() as connection:
        with connection.cursor() as cursor:
            # Oracle: LOWER(RAWTOHEX(coloana_raw)) pentru comparare textuala
            sql = '''
                  SELECT t.uuid_tranzactie, t.id_utilizator, u.email, t.nr_bilete, t.revendicat
                  FROM tranzactie t
                           JOIN utilizator u ON t.id_utilizator = u.id_utilizator
                  WHERE LOWER(RAWTOHEX(t.uuid_tranzactie)) = :q
                     OR LOWER(u.email) LIKE :q_like
                  '''
            cursor.execute(sql, q=clean_uuid_query, q_like=f"%{search_query}%")

            nume_coloane = [col[0].lower() for col in cursor.description]
            cursor.rowfactory = lambda *args: dict(zip(nume_coloane, args))

            rezultate = cursor.fetchall()

            # Conversie bytes -> hex string ca să poată fi serializat în JSON
            for rez in rezultate:
                if isinstance(rez['uuid_tranzactie'], bytes):
                    rez['uuid_tranzactie'] = rez['uuid_tranzactie'].hex()

            return jsonify(rezultate), 200


@app.route('/api/admin/add-transaction', methods=['POST'])
@admin_required
def api_add_transaction():
    date = request.get_json(silent=True) or {}
    email = (date.get('email') or '').strip()

    try:
        nr_bilete = int(date.get('nr_bilete'))
    except (TypeError, ValueError):
        return jsonify({"eroare": "Număr de bilete invalid."}), 400
    if not 1 <= nr_bilete <= 20:
        return jsonify({"eroare": "Numărul de bilete trebuie să fie între 1 și 20."}), 400

    uid_tranzactie = secrets.token_hex(16)

    with pool.acquire() as connection:
        with connection.cursor() as cursor:
            cursor.execute('SELECT id_utilizator FROM utilizator WHERE email = :email', email=email)
            user_row = cursor.fetchone()

            if not user_row:
                return jsonify({"eroare": "Nu există un cont cu acest email."}), 404

            id_user = user_row[0]

            # Am schimbat :uid in :uuid_tx
            sql = "INSERT INTO tranzactie (uuid_tranzactie, id_utilizator, nr_bilete, revendicat) VALUES (:uuid_tx, :id, :nr, 0)"
            cursor.execute(sql, uuid_tx=uid_tranzactie, id=id_user, nr=nr_bilete)
            connection.commit()

    email_trimis = trimite_email_bilet(email, uid_tranzactie, nr_bilete)
    mesaj_succes = "Tranzacție înregistrată. Email-ul a fost trimis cu succes!" if email_trimis else "Tranzacție înregistrată, dar email-ul NU a putut fi trimis."

    return jsonify({
        "mesaj": mesaj_succes,
        "uid_tranzactie": uid_tranzactie
    }), 201


@app.route('/api/admin/validate-transaction', methods=['POST'])
@admin_required
def api_validate_transaction():
    uid_tranzactie = (request.get_json(silent=True) or {}).get('uuid', '')
    clean_uid = uid_tranzactie.replace('-', '').upper()

    with pool.acquire() as connection:
        with connection.cursor() as cursor:
            # Am schimbat :uid in :uuid_tx
            cursor.execute("SELECT revendicat, nr_bilete FROM tranzactie WHERE RAWTOHEX(uuid_tranzactie) = :uuid_tx",
                           uuid_tx=clean_uid)
            tx_row = cursor.fetchone()

            if not tx_row:
                return jsonify({"eroare": "Tranzacție inexistentă"}), 404

            nr_bilete = tx_row[1]

            # Am schimbat :uid in :uuid_tx
            cursor.execute(
                "UPDATE tranzactie SET revendicat = 1 WHERE RAWTOHEX(uuid_tranzactie) = :uuid_tx AND revendicat = 0",
                uuid_tx=clean_uid)
            if cursor.rowcount == 0:
                return jsonify({"deja_folosit": True}), 400

            connection.commit()
            return jsonify({"mesaj": "Tranzacție validată", "nr_bilete": nr_bilete}), 200


@app.route('/api/admin/make-user-admin', methods=['POST'])
@admin_required
def api_make_user_admin():
    email = (request.get_json(silent=True) or {}).get('email')

    with pool.acquire() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id_utilizator FROM utilizator WHERE email = :email", email=email)
            utilizator_row = cursor.fetchone()

            if not utilizator_row:
                return jsonify({"eroare": "User inexistent"}), 404

            id_utilizator = utilizator_row[0]

            cursor.execute('''UPDATE utilizator
                              SET este_admin = 1
                              WHERE id_utilizator = :id_utilizator''',
                           id_utilizator=id_utilizator)
            connection.commit()

            return jsonify({"mesaj": "User-ul a fost facut admin"}), 200


if __name__ == '__main__':
    # debug și acces din rețea doar dacă le ceri explicit (debug=True pe 0.0.0.0 expune consola Werkzeug)
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=5000,
        debug=os.getenv("FLASK_DEBUG") == "1",
    )