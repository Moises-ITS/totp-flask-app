from cryptography.fernet import Fernet
import pyotp, bcrypt, json, os, qrcode, re
from flask import Flask, render_template, request, redirect, url_for, flash, session
#--------------------------
#flask setup
#---------------------------
app = Flask(__name__)
app.secret_key = "supersecretkey"
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
    
def load_users():
    if not os.path.exists("user_data.json"):
        with open("user_data.json", "w") as f:
            json.dump({}, f)
    with open("user_data.json", "r") as f:
        try:
            return json.load(f)
        except:
            return {}

def save_users(users):
    with open("user_data.json", 'w') as f:
        json.dump(users, f, indent=2)

#----------------------------------------------
# functions
#----------------------------------------------

def login_user(username, password):
    users = load_users()
    username = username.strip()
    password = password.strip()

    if username not in users:
        return False, "Username does not exist"
    
    hashed_pw = users[username]["password"]
    if not bcrypt.checkpw(password.encode(), hashed_pw.encode()):
        return False, "Incorrect Password"
    key = load_key()
    fernet = Fernet(key)
    encrypted_secret = users[username]['secret']
    secret = fernet.decrypt(encrypted_secret.encode()).decode()
    
    session["username"] = username
    #code for login QR
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
    qr_path = os.path.join("static", qr_filename)
    img.save(qr_path)

    session["qr_path"] = qr_filename
    session["username"] = username

    return True, "login successful! Here's your QR code."

def register_user(username, password):
    key = load_key()
    fernet = Fernet(key)
    users = load_users()
    username = username.strip()
    password = password.strip()
    if username in users:
        return False, "username already exists"
    
    secret = pyotp.random_base32()
    encrypted_secret = fernet.encrypt(secret.encode()).decode()
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    users[username] = {
        "password" : hashed_password,
        "secret" : encrypted_secret
    }
    save_users(users)

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
    qr_path = os.path.join("static", qr_filename)
    img.save(qr_path)

    return True, qr_filename

def verify_token(token):
    key = load_key()
    fernet = Fernet(key)
    username = session.get("username")
    users = load_users()
    encrypted_secret = users[username]["secret"]
    secret = fernet.decrypt(encrypted_secret.encode()).decode()
    totp = pyotp.TOTP(secret)
    if totp.verify(token):
        return True, "Valid token"
    return False, "Invalid token"

#----------------------------------------------
#Routes
#---------------------------------------------

@app.route("/")
def menu():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        valid, msg = password_complexity(password)
        if not valid:
            flash(msg, "danger")
            return redirect(url_for("register"))

        success, result = register_user(username, password)
        if not success:
            flash(result, "danger")
            return redirect(url_for("register"))

        flash("User registered successfully! Scan your QR code below.", "success")
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
    qr_path = session.get("qr_path")
    if not qr_path:
        flash("No QR code found. Please register first.", "danger")
        return redirect(url_for("register"))
    return render_template("show_qr.html", qr_path=qr_path)

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
    return render_template("home.html")

@app.route("/Logout")
def Logout():
    qr_path = session.get("qr_path")
    username = session.get("username")
    qr_path.pop()
    username.pop()
    return render_template("index.html")
    
#---------------------------------------------
#run app
#---------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

