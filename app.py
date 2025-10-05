from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded #show error message
import os

# --- App & DB setup ---
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") #for safety of session data, etc

#rate limiter setup
limiter = Limiter(
    get_remote_address, #identify user by ip
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# SQLite DB in project root file 'database.db'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "database.db") #connect file path to database
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app) #link flask app with sql

class User(db.Model): 
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password): #when register
        self.password_hash = generate_password_hash(password)

    def check_password(self, password): # when login
        return check_password_hash(self.password_hash, password)
    
# Create tables if they don't exist
with app.app_context():
    db.create_all()

@app.errorhandler(RateLimitExceeded)
def ratelimit_handler(e):
    flash("Too many requests! Please wait a moment before trying again.", "error")
    return redirect(url_for("home"))

@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("index.html", username=session.get("username"))

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("4 per minute")
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not (username and email and password):
            flash("Please fill all fields", "error")
            return redirect(url_for("register"))

        # Check existing user
        existing_user = User.query.filter( #search with the condition
            (User.username == username) | (User.email == email)
        ).first() 
        if existing_user:
            flash("Username or email already exists", "error")
            return redirect(url_for("register"))

        user = User(username=username, email=email)
        user.set_password(password)  # hash password
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("9 per minute")
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first() #find the row where username match

        if user and user.check_password(password):
            session["user_id"] = user.id
            session["username"] = user.username
            flash(f"Welcome, {user.username}!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password", "error")
            return render_template("login.html")
        
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out.", "info")
    return redirect(url_for("login"))

@app.route("/users")
def show_users():
    if "user_id" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))
    
    user = User.query.get(session["user_id"])
    if not user or not user.is_admin:
        flash("Access denied! Admins only.", "error")
        return redirect(url_for("home"))
    
    users = User.query.all()
    return render_template("users.html", users=users)

if __name__ == "__main__":
    app.run(debug=True) #auto reload/ show detailed error
