"""Authentication blueprint."""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from .. import db, limiter
from ..forms import LoginForm, PasswordUpdateForm, RegistrationForm, ResetForm
from ..models import User
from ..services.auth import generate_reset_token, verify_reset_token

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("quotes.new_quote"))
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash("Email already registered", "danger")
        else:
            user = User(email=form.email.data.lower())
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("auth.login"))
    return render_template("register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", override_defaults=False)
def login():
    if current_user.is_authenticated:
        return redirect(url_for("quotes.new_quote"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for("quotes.new_quote"))
        flash("Invalid credentials", "danger")
    return render_template("login.html", form=form)


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@bp.route("/reset", methods=["GET", "POST"])
@limiter.limit("5 per minute", override_defaults=False)
def issue_reset_token():
    form = ResetForm()
    token = None
    if form.validate_on_submit():
        token = generate_reset_token(form.email.data.lower())
        flash("Token generated. Use it to reset your password.", "info")
    return render_template("reset.html", form=form, token=token)


@bp.route("/reset/confirm", methods=["GET", "POST"])
@limiter.limit("1 per 15 minute", override_defaults=False)
def reset_password():
    form = PasswordUpdateForm()
    if form.validate_on_submit():
        email = verify_reset_token(form.token.data)
        if not email:
            flash("Invalid or expired token", "danger")
        else:
            user = User.query.filter_by(email=email.lower()).first()
            if not user:
                flash("Unknown user", "danger")
            else:
                user.set_password(form.password.data)
                db.session.commit()
                flash("Password updated", "success")
                return redirect(url_for("auth.login"))
    return render_template("reset_confirm.html", form=form)
