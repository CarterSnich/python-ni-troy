import traceback
import math
from os import error
from warnings import catch_warnings
from flask import Flask, render_template, request, redirect, url_for, flash, session
import database
from forms import SignUpForm, SignInForm
from werkzeug.security import generate_password_hash, check_password_hash
from sqlite3 import IntegrityError
from werkzeug.exceptions import HTTPException
from middleware import MethodRewriteMiddleware, AuthMiddleware
from forms import check_password_format, validate_email


app = Flask(__name__)
app.config.from_mapping(
    SECRET_KEY="dev",
    DATABASE="db.sqlite",
)
app.wsgi_app = MethodRewriteMiddleware(app.wsgi_app)
app.wsgi_app = AuthMiddleware(
    app, app.wsgi_app, protected_prefixes=("/users", "/signout")
)
database.init_app(app)


@app.errorhandler(HTTPException)
def handle_http_exception(e):
    return (
        render_template(
            "http-error.jinja",
            code=e.code,
            name=e.name,
            description=e.description,
        ),
        e.code,
    )


@app.route("/", methods=["GET", "POST"])
def index():
    form = SignInForm()

    if request.method == "POST":
        db = database.get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (form.username.data,)
        ).fetchone()

        if user and check_password_hash(user["password"], form.password.data):
            session["user"] = {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "address": user["address"],
                "username": user["username"],
            }
            return redirect(url_for("users"))

        flash("Password is incorrect." if user else "User not found.", "error")

    if request.args.get("username"):
        form.username.data = request.args.get("username")

    return render_template("index.jinja", form=form)


@app.route("/signup", methods=["GET", "POST"])
def signup():
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
            flash("Sign up successfully")
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


@app.route("/users", methods=["GET", "POST"])
def users():
    form = SignUpForm()
    user = session.get("user")

    db = database.get_db()

    if request.method == "POST":
        try:
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
            flash("User added successfully.")
            return redirect(url_for("users"))
        except IntegrityError as err:
            msg = str(err)
            if msg.startswith("UNIQUE constraint failed:"):
                parts = msg.split(": ")[1].split(".")
                table = parts[0]
                column = parts[1]
                flash(f"{column.capitalize()} already exist.", "error")
            else:
                flash("Failed to add user.", "error")

    users = db.execute("SELECT * FROM users").fetchall()

    return render_template("users.jinja", user=user, users=users, form=form)


@app.route("/users/<int:id>", methods=["PATCH", "PUT", "DELETE"])
def users_id(id: int):
    user = session.get("user")
    try:
        db = database.get_db()

        match request.method:
            case "PATCH" | "PUT":
                column = list(request.form.keys())[0]
                value = request.form.get(column)

                if len(value) <= 0:
                    raise ValueError("Field must not be empty.")

                match column:
                    case "email":
                        validate_email(value)
                    case "password":
                        check_password_format(value)
                        value = generate_password_hash(value)

                db.execute(
                    f"UPDATE users SET {column} = ? WHERE id = ?",
                    (value, id),
                )
                db.commit()
                flash(f"Updated User ID No. {id}")
            case "DELETE":
                db.execute("DELETE FROM users WHERE id = ?", (id,))
                db.commit()
                flash(f"User ID No. {id} deleted successfully.")
                print(f"Auth: {type(user['id'])}({user['id']})")
                print(f"Pass: {type(id)}({id})")
                if user["id"] == id:
                    return redirect(url_for("signout"))
    except Exception as e:
        traceback.print_exc()
        flash(str(e), "error")

    return redirect(url_for("users"))


@app.route("/signout")
def signout():
    session.pop("user", None)
    flash("You have successfully logged out.", "info")
    return redirect(url_for("index"))
