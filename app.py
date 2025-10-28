from cryptography.fernet import Fernet
import pyotp, bcrypt, json, os, qrcode, re
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import time
from datetime import datetime
#--------------------------
#flask setup
#---------------------------
app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), "static"), template_folder=os.path.join(os.path.dirname(__file__), "templates"))
app.secret_key = "supersecretkey"
#------------------------------
#SQLite database
#------------------------------
app.config['SQLALCHEMY_DATABASE_URI' ] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    totp_secret = db.Column(db.String(200), nullable=False)
    login_attempts = db.Column(db.Integer, default=0)
    lockout_time = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class LoginLog(db.Model):
    id = db.Column(db.Integer, unique=True, nullable=False, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='logs')
#------------------------------
#helper functions
#-------------------------------

def password_complexity(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=;']", password):
        return False, "Password must include at least one special character."

    return True, "Password is strong."

def load_key():
    with open("secret.key", "rb") as key_file:
        return key_file.read()

#----------------------------------------------
# functions
#----------------------------------------------

def login_user(username, password):
    username = username.strip()
    password = password.strip()
    user = User.query.filter_by(username=username).first()

    if not user:
        return False, "Username does not exist"

    if user.lockout_time and time.time() < user.lockout_time:
        remaining = int((user.lockout_time - time.time()) / 60)
        return False, f"Too many failed attempts. Try again in {remaining} minute(s)"
    
    if not bcrypt.checkpw(password.encode(), user.password.encode()):
        user.login_attempts += 1
        if user.login_attempts >= 3:
            user.lockout_time = time.time() + 300
            user.login_attempts = 0
            db.session.commit()
            return False, "Too many failed attempts. You are locked out for 5 minutes."
        db.session.commit()
        return False, "Incorrect Password"

    user.login_attempts = 0
    user.lockout_time = None
    db.session.commit()

    session["username"] = username
    
    log = LoginLog(user_id=user.id)
    db.session.add(log)
    db.session.commit()

    return True, "login successful!"

def register_user(username, password):
    fernet = Fernet(load_key())
    username = username.strip()
    password = password.strip()
    
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return False, "Username already exists."

    secret = pyotp.random_base32()
    encrypted_secret = fernet.encrypt(secret.encode()).decode()
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    new_user = User(username=username, password=hashed_password, totp_secret=encrypted_secret)
    db.session.add(new_user)
    db.session.commit()

    return True, "Successfully created User."

def verify_token(token):
    username = session.get("username")
    user = User.query.filter_by(username=username).first()
    fernet = Fernet(load_key())
    secret = fernet.decrypt(user.totp_secret.encode()).decode()

    totp = pyotp.TOTP(secret)
    if totp.verify(token):
        return True, "Valid token"
    return False, "Invalid token"
    
#----------------------------------------------
#Routes
#---------------------------------------------

@app.route("/", endpoint="index")
def menu():
    return render_template("index.html")

@app.route("/logintime")
def logintime():
    username = session.get("username")
    if not username:
        flash("Login first.", "warning")
        return redirect(url_for("login"))
    user = User.query.filter_by(username=username).first()
    logs = LoginLog.query.filter_by(user_id=user.id).order_by(LoginLog.timestamp.desc()).all()
    return render_template("logintime.html", logs=logs, username=username)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        valid, msg = password_complexity(password)
        if not valid:
            flash(msg, "danger")
            return redirect(url_for("register"))

        success, msg = register_user(username, password)
        if not success:
            flash(msg, "danger")
            return redirect(url_for("register"))

        flash(msg, "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        valid, msg = login_user(username, password)
        if not valid:
            flash(msg, "danger")
            return redirect(url_for("login"))
        flash(msg, "success")
        return redirect(url_for("home"))
    return render_template("login.html")

@app.route("/show_qr")
def show_qr():
    username = session.get("username")
    if not username:
        flash("Please login first.", "danger")
        return redirect(url_for("login"))
    user = User.query.filter_by(username=username).first()
    fernet = Fernet(load_key())
    secret = fernet.decrypt(user.totp_secret.encode()).decode()

    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="MyTOTPApp")

    qr = qrcode.QRCode(
        version=1,  # 1 = smallest size, can increase if needed
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,  # each box will be 10x10 pixels
        border=4      # border width (minimum is 4 for most scanners)
    )
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    if not os.path.exists("static"):
        os.makedirs("static")

    qr_filename = f'{username}_qrcode.png'
    qr_path = os.path.join(app.static_folder, qr_filename)
    img.save(qr_path)

    session["qr_path"] = qr_filename

    return render_template("show_qr.html", qr_path=qr_filename)

@app.route("/test", methods=["GET", "POST"])
def test():
    if "username" not in session:
        flash("Please log in first", "warning")
        return redirect(url_for("login"))
    if request.method == "POST":
        token = request.form.get("token")

        valid, msg = verify_token(token)
        if not valid:
            flash(msg, "danger")
        flash(msg, "success")
    return render_template("test.html")

@app.route("/home")
def home():
    if "username" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    username = session["username"]
    return render_template("home.html", username=username)

@app.route("/Logout")
def Logout():
    session.pop("qr_path", None)
    session.pop("username", None)
    flash("Logged out successfully", "success")
    return render_template("index.html")
    
#---------------------------------------------
#run app
#---------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
