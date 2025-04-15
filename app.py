from flask import Flask, render_template, request, redirect, url_for, flash, session
import database
from forms import SignUpForm, SignInForm
from werkzeug.security import generate_password_hash, check_password_hash
from haikus import haikus
import random


app = Flask(__name__)
app.config.from_mapping(
    SECRET_KEY="dev",
    DATABASE="db.sqlite",
)
database.init_app(app)


@app.route("/", methods=["GET", "POST"])
def index():
    if "user" in session:
        return redirect(url_for("welcome"))
    return render_template("index.jinja")


@app.route("/signin", methods=["GET", "POST"])
def signin():
    if session.get("user"):
        return redirect(url_for("welcome"))

    form = SignInForm()

    if request.method == "POST":
        db = database.get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (form.username.data,)
        ).fetchone()

        if user and check_password_hash(user["password"], form.password.data):
            session["user"] = {
                "name": user["name"],
                "email": user["email"],
                "address": user["address"],
                "username": user["username"],
            }
            return redirect("/welcome")

        flash("Password is incorrect." if user else "User not found.", "error")

    return render_template("signin.jinja", form=form)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("user"):
        return redirect(url_for("welcome"))

    form = SignUpForm()

    if request.method == "POST" and form.validate_on_submit():
        db = database.get_db()
        db.execute(
            "INSERT INTO users (name, email, address, username, password)"
            "VALUES (?, ?, ?, ?, ?)",
            (
                form.name.data,
                form.email.data,
                form.address.data,
                form.username.data,
                generate_password_hash(form.password.data),
            ),
        )
        db.commit()

        flash("Sign up successfully!")
        return redirect(url_for("signin"))

    return render_template("signup.jinja", form=form)


@app.route("/welcome")
def welcome():
    user = session.get("user")

    if user:
        haiku = random.choice(haikus)
        filled_haiku = (
            haiku.replace("%name%", user["name"])
            .replace("%email%", user["email"])
            .replace("%username%", user["username"])
            .replace("%address%", user["address"])
        )
        return render_template("welcome.jinja", haiku=filled_haiku)

    flash("Please, sign in first.", "warning")
    return redirect("/")


@app.route("/signout")
def signout():
    session.pop("user", None)
    flash("You have successfully logged out.", "info")
    return redirect(url_for("index"))
