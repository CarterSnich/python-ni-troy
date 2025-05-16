from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, ValidationError
from wtforms.validators import DataRequired
import re


def validate_email(value: str):
    email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    if not re.match(email_regex, value):
        raise ValueError("Invalid email format.")


def check_password_format(password: str):
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters long.")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must include a lowercase letter.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must include an uppercase letter.")
    if not re.search(r"\d", password):
        raise ValueError("Password must include a digit.")
    if not re.search(r'[!@#$%^&*()\-_=+{}\[\]:;"\'<>,.?/~`|\\]', password):
        raise ValueError("Password must include at least one symbol.")


def validate_password_format(form, field):
    try:
        check_password_format(field.data)
    except ValueError as e:
        raise ValidationError(str(e))


class SignUpForm(FlaskForm):
    name = StringField(label="Name", id="name", validators=[DataRequired()])
    email = EmailField(label="Email", id="email", validators=[DataRequired()])
    address = StringField(label="Address", id="address", validators=[DataRequired()])
    username = StringField(
        label="Username",
        id="username",
        validators=[DataRequired()],
    )
    password = PasswordField(
        label="Password",
        id="password",
        validators=[DataRequired(), validate_password_format],
    )


class SignInForm(FlaskForm):
    username = StringField(
        label="Username",
        id="username",
        validators=[DataRequired()],
    )
    password = PasswordField(
        label="Password", id="password", validators=[DataRequired()]
    )
