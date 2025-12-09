"""WTForms definitions."""
from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import BooleanField, FloatField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length


class RegistrationForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm = PasswordField("Confirm", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember me")
    submit = SubmitField("Login")


class ResetForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Issue token")


class PasswordUpdateForm(FlaskForm):
    token = StringField("Token", validators=[DataRequired()])
    password = PasswordField("New Password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField("Reset password")


class QuoteForm(FlaskForm):
    mode = SelectField("Mode", choices=[("hotshot", "Hotshot"), ("air", "Air")], validators=[DataRequired()])
    origin_zip = StringField("Origin ZIP", validators=[DataRequired()])
    destination_zip = StringField("Destination ZIP", validators=[DataRequired()])
    weight_lbs = FloatField("Weight (lbs)", validators=[DataRequired()])
    length_in = FloatField("Length (in)")
    width_in = FloatField("Width (in)")
    height_in = FloatField("Height (in)")
    accessorials = StringField("Accessorial codes (comma separated)")
    submit = SubmitField("Quote")
