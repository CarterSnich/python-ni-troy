from flask import Flask, render_template, request, redirect, url_for, flash, session
import database
from forms import SignUpForm, SignInForm
from werkzeug.security import generate_password_hash, check_password_hash
from haikus import haikus
import random
from sqlite3 import IntegrityError
from werkzeug.exceptions import HTTPException


app = Flask(__name__)
app.config.from_mapping(
    SECRET_KEY="dev",
    DATABASE="db.sqlite",
)
database.init_app(app)


@app.errorhandler(HTTPException)
def handle_http_exception(e):
    return (
        render_template(
            "http-error.jinja", code=e.code, name=e.name, description=e.description
        ),
        e.code,
    )


@app.route("/", methods=["GET", "POST"])
def index():
    if "user" in session:
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

    if request.args.get("username"):
        form.username.data = request.args.get("username")

    return render_template("index.jinja", form=form)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("user"):
        return redirect(url_for("welcome"))

    form = SignUpForm()

    if request.method == "POST" and form.validate_on_submit():
        try:
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
            return redirect(url_for("index", username=form.username.data))
        except IntegrityError as err:
            flash("Sign up failed.", category="error")
            msg = str(err)
            if msg.startswith("UNIQUE constraint failed:"):
                parts = msg.split(": ")[1].split(".")
                table = parts[0]
                column = parts[1]
                form[column].errors.append(f"{column.capitalize()} already exist.")

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
    if "user" in session:
        session.pop("user", None)
        flash("You have successfully logged out.", "info")

    return redirect(url_for("index"))
