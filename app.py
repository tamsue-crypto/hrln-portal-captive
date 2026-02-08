from flask import Flask, render_template, request, redirect,  url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import date, datetime, timedelta
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps
import re
import os
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# == Core app ==
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

# == Google Login ==

app.config["GOOGLE_CLIENT_ID"] = os.environ.get("GOOGLE_CLIENT_ID")
app.config["GOOGLE_CLIENT_SECRET"] = os.environ.get("GOOGLE_CLIENT_SECRET")

app.permanent_session_lifetime = timedelta(minutes=10)

oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    }
)

# == Email ==
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_USERNAME")

mail = Mail(app)

# == App ==
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///proj.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# == Token ==
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# == User Model ==
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100), nullable = False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    cpf = db.Column(db.String(11), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable = False)
    birthday = db.Column(db.Date, nullable=False)

with app.app_context():
    db.create_all()
    if os.environ.get("CREATE_ADMIN") == "1":
        if not User.query.filter_by(email=os.environ.get("ADMIN_EMAIL")).first():
            user = User(
                name="Mateus",
                email=os.environ.get("ADMIN_EMAIL"),
                cpf="00000000000",
                birthday=date(1990, 1, 1),
                password=generate_password_hash(os.environ.get("ADMIN_PASSWORD"))
            )
            db.session.add(user)
            db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# == Auth ==
def guest_only(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        return view(*args, **kwargs)
    return wrapped_view

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[^A-Za-z0-9]", password)
    )

# == Routes ==
@app.route("/")
def index():
    if current_user.is_authenticated:
        return render_template("index.html", logged=True, user=current_user)
    else:
        return render_template('index.html')

@app.route("/login", methods=["GET", "POST"])
@guest_only
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if not user:
            return render_template("login.html", email_error=True)
        
        if not check_password_hash(user.password, password):
            return render_template("login.html", pass_error=True, email=email)
        
        login_user(user)
        return redirect(url_for("index"))
    
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
@guest_only
def signup():
    errors = {}
    if request.method == "POST":
        name = request.form.get("username")
        cpf_raw = request.form.get("cpf")
        birthday_raw = request.form.get("birthday")
        email = request.form.get("email")
        password = request.form.get("password")
        conf_pass = request.form.get("conf_pass")

        cpf = "".join(filter(str.isdigit, cpf_raw))
        birthday_numbers = "".join(filter(str.isdigit, birthday_raw))

        existing_user = User.query.filter(
            or_(
                    User.email == email,
                    User.cpf == cpf
                )
            ).first()
    
        if ".com" not in email:
            errors["email"] = "Email inválido"

        if len(cpf) != 11:
            errors["cpf"] = "Cpf inválido"

        if len(birthday_numbers) != 8:
            errors["bday"] = "Data invalida"

        if not is_strong_password(password):
             errors["pass"] = "Senha muito fraca"
        elif password != conf_pass:
            errors["pass"] = "As senhas não coincidem"

        if existing_user:
                if existing_user.email == email:
                    errors["email"] = "Email já cadastrado"
                if existing_user.cpf == cpf:
                    errors["cpf"] = "Cpf já cadastrado"

        if len(errors) > 0:
            return render_template("signup.html", errors=errors)

        day = int(birthday_numbers[:2])
        month = int(birthday_numbers[2:4])
        year = int(birthday_numbers[4:])

        birthday = date(year, month, day)

        user = User(
            name=name,
            email=email,
            cpf=cpf,
            birthday=birthday,
            password=generate_password_hash(password)
        )

        db.session.add(user)
        db.session.commit()

        return redirect(url_for("index"))
    return render_template("signup.html", errors={})

@app.route("/forgot_password", methods=["GET", "POST"])
@guest_only
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()

        if not user:
            return render_template("forgot_pass.html", error="Este email não está cadastrado")

        token = serializer.dumps(email, salt="reset-password")

        reset_link = url_for("reset_password", token=token, _external=True)

        msg = Message(
            subject="Recuperação de senha",
            recipients=[email],
            body=f"""
Olá {user.name},

Você solicitou a recuperação de senha.

Clique no link abaixo para criar uma nova senha:
{reset_link}

Em link expira em 15 minutos.
"""
        )

        try:
            mail.send(msg)
        except Exception as e:
            print(e)
            return "Erro ao enviar email", 500

        return render_template("forgot_pass.html", success=True)
    return render_template("forgot_pass.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(
            token,
            salt="reset-password",
            max_age=900
        )

    except SignatureExpired:
        return "Link expirado", 400
    except BadSignature:
        return "Link inválido", 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return "Usuário não encontrado", 404

    if request.method == "POST":
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        if not is_strong_password(password):
             return render_template("reset_password.html", error="Senha muito fraca")
        elif password != confirm:
            return render_template("reset_password.html", error="As senhas não coincidem")

        user.password = generate_password_hash(password)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("reset_password.html")

@app.route("/_debug/users")
@login_required
def debug_users():
    if current_user.email != "mateusbarros45@yahoo.com":
        return "Acesso negado", 403

    users = User.query.all()
    return {
        "total": len(users),
        "users": [
            {
                "id": u.id,
                "name": u.name,
                "email": u.email,
                "cpf": u.cpf,
                "birthday": u.birthday
            } for u in users
        ]
    }

@app.route("/login/google")
def login_google():
    session.permanent = True
    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/login/google/callback")
def google_callback():
    token = google.authorize_access_token()
    
    
    resp = google.get("https://openidconnect.googleapis.com/v1/userinfo")
    user_info = resp.json()

    email = user_info["email"]
    name = user_info["name"]

    user = User.query.filter_by(email=email).first()

    if user:
        login_user(user)
        return redirect(url_for("index"))
    
    session["google_user"] = {
        "email": email, 
        "name": name
    }

    return redirect(url_for("complete_signup"))

@app.route("/complete-signup", methods=["GET", "POST"])
@guest_only
def complete_signup():
    google_user = session.get("google_user")

    if not google_user:
        return redirect(url_for("login"))
    
    errors = {}

    if request.method == "POST":
        cpf_raw = request.form.get("cpf")
        birthday_raw = request.form.get("birthday")
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        cpf = "".join(filter(str.isdigit, cpf_raw))
        birthday_numbers = "".join(filter(str.isdigit, birthday_raw))

        if User.query.filter_by(cpf=cpf).first():
            errors["cpf"] = "CPF já cadastrado"
        elif len(cpf) != 11:
            errors["cpf"] = "CPF inválido"

        if len(birthday_numbers) != 8:
            errors["bday"] = "Data inválida"

        if not is_strong_password(password):
            errors["pass"] = "Senha muito fraca"
        elif password != confirm:
            errors["pass"] = "As senhas não coincidem"

        if errors:
            return render_template("complete_signup.html", errors=errors, user=google_user)

        day = int(birthday_numbers[:2])
        month = int(birthday_numbers[2:4])
        year = int(birthday_numbers[4:])

        birthday = date(year, month, day)

        user = User(
            name=google_user["name"],
            email=google_user["email"],
            cpf=cpf,
            birthday=birthday,
            password=generate_password_hash(password)
        )

        db.session.add(user)
        db.session.commit()

        session.pop("google_user")
        login_user(user)

        return redirect(url_for("index"))

    return render_template("complete_signup.html", user=google_user, errors=errors)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))