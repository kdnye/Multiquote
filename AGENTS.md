 (cd "$(git rev-parse --show-toplevel)" && git apply --3way <<'EOF' 
diff --git a/README.md b/README.md
index c878222fa27f0a2963e3ce9109c026632a5a371b..0ced83cd1ff3d233c05826c95bd288002905daba 100644
--- a/README.md
+++ b/README.md
@@ -138,25 +138,57 @@ to CSV (`.csv`) or Markdown (`.md`/`.markdown`) so you can hand it to purchasing
 or paste it into documentation.
 
 ## Getting Started
 
 1. Create and activate a virtual environment (optional but recommended).
 2. Install dependencies:
 
    ```bash
    pip install -r requirements.txt
    ```
 
    This pulls in `qrcode[pil]` (version 7.4 or newer) for QR generation. If
    reproducibility is critical for your workflow, feel free to pin an exact version in
    `requirements.txt`.
 
 3. Tweak the script constants for your current task and run the script with Python 3.9+
    (Windows required for `mass_print.py`).
 
 ## Notes
 
 * Treat these scripts as templates—copy, rename, and customize them for the job at
   hand.
 * Add new helpers to the repository as you build them so everything stays in one place.
 
 Happy hacking!
+
+## Quote Tool
+
+This repository now includes a lightweight re-implementation of the Quote Tool web app. It uses Flask, SQLAlchemy, WTForms, and Flask-Login to deliver HTML pages and JSON APIs for hotshot and air freight quoting.
+
+### Quick start
+
+1. Create a virtual environment and install dependencies:
+
+   ```bash
+   pip install -r requirements.txt
+   ```
+
+2. Run the development server:
+
+   ```bash
+   python -m quote_tool.app
+   ```
+
+   The app loads default configuration suitable for local SQLite usage. Set `DATABASE_URL`, `SECRET_KEY`, and mail or Google Maps keys in a `.env` file or environment variables for production.
+
+3. Seed reference data by opening a Python shell and inserting rate rows into the tables in `quote_tool/app/models.py`. You can adapt the fixtures in `tests/test_quote_logic.py` as a starting point.
+
+### Packaging for Windows
+
+Use `pyinstaller` to build a single-file executable:
+
+```bash
+pyinstaller --onefile -n quote_tool run_quote_tool.py
+```
+
+Create `run_quote_tool.py` with a simple `from quote_tool import create_app` and `app = create_app()` entry point before packaging.
diff --git a/quote_tool/__init__.py b/quote_tool/__init__.py
new file mode 100644
index 0000000000000000000000000000000000000000..b94a1e85fb4caa4eb659956d6fc53f68d5b6440f
--- /dev/null
+++ b/quote_tool/__init__.py
@@ -0,0 +1,3 @@
+from .app import create_app
+
+__all__ = ["create_app"]
diff --git a/quote_tool/app/__init__.py b/quote_tool/app/__init__.py
new file mode 100644
index 0000000000000000000000000000000000000000..518f3b33d303386b1b6776cf09d4d21f9bba89fe
--- /dev/null
+++ b/quote_tool/app/__init__.py
@@ -0,0 +1,65 @@
+"""Application factory for Quote Tool.
+
+This module wires together Flask extensions, blueprints, and configuration. The goal
+is to mirror the original feature set in a compact, maintainable structure while
+preserving security defaults such as CSRF protection, login management, and rate
+limiting hooks.
+"""
+from __future__ import annotations
+
+import os
+from datetime import timedelta
+from typing import Any, Dict
+
+from flask import Flask
+from flask_sqlalchemy import SQLAlchemy
+from flask_wtf import CSRFProtect
+from flask_login import LoginManager
+from flask_limiter import Limiter
+from flask_limiter.util import get_remote_address
+
+from .config import Config
+
+# Flask extensions
+csrf = CSRFProtect()
+db = SQLAlchemy()
+login_manager = LoginManager()
+# Limiter can be configured to be no-op when storage is unavailable
+limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
+
+
+def create_app(config_overrides: Dict[str, Any] | None = None) -> Flask:
+    """Create and configure the Flask application.
+
+    Args:
+        config_overrides: Optional mapping of values that override the default
+            :class:`Config` attributes. Useful for tests.
+
+    Returns:
+        Configured :class:`~flask.Flask` application instance.
+    """
+    app = Flask(__name__, instance_relative_config=True, template_folder="templates")
+    app.config.from_object(Config())
+    app.config.update(config_overrides or {})
+
+    # Initialise extensions
+    csrf.init_app(app)
+    db.init_app(app)
+    login_manager.init_app(app)
+    login_manager.login_view = "auth.login"
+    limiter.init_app(app)
+
+    # Register blueprints
+    from .blueprints import auth, quotes, admin
+
+    app.register_blueprint(auth.bp)
+    app.register_blueprint(quotes.bp)
+    app.register_blueprint(admin.bp)
+
+    with app.app_context():
+        db.create_all()
+
+    return app
+
+
+__all__ = ["create_app", "db", "csrf", "login_manager", "limiter"]
diff --git a/quote_tool/app/__main__.py b/quote_tool/app/__main__.py
new file mode 100644
index 0000000000000000000000000000000000000000..88a6eed22f10f33a47eab7d5ba758598421a27e6
--- /dev/null
+++ b/quote_tool/app/__main__.py
@@ -0,0 +1,6 @@
+from . import create_app
+
+app = create_app()
+
+if __name__ == "__main__":
+    app.run(debug=True)
diff --git a/quote_tool/app/blueprints/__init__.py b/quote_tool/app/blueprints/__init__.py
new file mode 100644
index 0000000000000000000000000000000000000000..9c40b6a7414f25d98ffa5dd8b7e5725a23b0318d
--- /dev/null
+++ b/quote_tool/app/blueprints/__init__.py
@@ -0,0 +1,3 @@
+from . import auth, quotes, admin
+
+__all__ = ["auth", "quotes", "admin"]
diff --git a/quote_tool/app/blueprints/admin.py b/quote_tool/app/blueprints/admin.py
new file mode 100644
index 0000000000000000000000000000000000000000..17458ba315df469091b99020b098e00abd97391f
--- /dev/null
+++ b/quote_tool/app/blueprints/admin.py
@@ -0,0 +1,17 @@
+"""Admin placeholder routes.
+
+The legacy system includes extensive admin tooling; this blueprint provides a
+minimal landing page that can be extended with rate importers and dashboards.
+"""
+from __future__ import annotations
+
+from flask import Blueprint, render_template
+from flask_login import login_required
+
+bp = Blueprint("admin", __name__, url_prefix="/admin")
+
+
+@bp.route("/")
+@login_required
+def dashboard():
+    return render_template("admin_dashboard.html")
diff --git a/quote_tool/app/blueprints/auth.py b/quote_tool/app/blueprints/auth.py
new file mode 100644
index 0000000000000000000000000000000000000000..0b0df8e1b80021d0e6ff851bfa8bb24b40317892
--- /dev/null
+++ b/quote_tool/app/blueprints/auth.py
@@ -0,0 +1,71 @@
+"""Authentication routes."""
+from __future__ import annotations
+
+from flask import Blueprint, flash, redirect, render_template, request, url_for
+from flask_login import current_user, login_required, login_user, logout_user
+from wtforms import Form, PasswordField, StringField
+from wtforms.validators import DataRequired, Email, Length
+
+from ..services import auth as auth_service
+from ..models import User
+from .. import db
+
+
+class RegisterForm(Form):
+    email = StringField("Email", validators=[DataRequired(), Email()])
+    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
+
+
+class LoginForm(Form):
+    email = StringField("Email", validators=[DataRequired(), Email()])
+    password = PasswordField("Password", validators=[DataRequired()])
+
+
+bp = Blueprint("auth", __name__, url_prefix="/auth")
+
+
+@bp.route("/register", methods=["GET", "POST"])
+def register():
+    if current_user.is_authenticated:
+        return redirect(url_for("quotes.new_quote"))
+    form = RegisterForm(request.form)
+    if request.method == "POST" and form.validate():
+        if User.query.filter_by(email=form.email.data).first():
+            flash("User already exists", "warning")
+        else:
+            auth_service.create_user(email=form.email.data, password=form.password.data)
+            flash("Registration complete. Please log in.", "success")
+            return redirect(url_for("auth.login"))
+    return render_template("register.html", form=form)
+
+
+@bp.route("/login", methods=["GET", "POST"])
+def login():
+    if current_user.is_authenticated:
+        return redirect(url_for("quotes.new_quote"))
+    form = LoginForm(request.form)
+    if request.method == "POST" and form.validate():
+        user = auth_service.authenticate(form.email.data, form.password.data)
+        if user:
+            login_user(user)
+            return redirect(url_for("quotes.new_quote"))
+        flash("Invalid credentials", "danger")
+    return render_template("login.html", form=form)
+
+
+@bp.route("/logout")
+@login_required
+def logout():
+    logout_user()
+    flash("Logged out", "info")
+    return redirect(url_for("auth.login"))
+
+
+@bp.route("/reset", methods=["GET", "POST"])
+def reset_password():
+    form = LoginForm(request.form)
+    token = None
+    if request.method == "POST" and form.validate():
+        token = auth_service.issue_reset_token()
+        flash("Password reset token generated; implement email delivery in production.", "info")
+    return render_template("reset.html", form=form, token=token)
diff --git a/quote_tool/app/blueprints/quotes.py b/quote_tool/app/blueprints/quotes.py
new file mode 100644
index 0000000000000000000000000000000000000000..6cd6679991e9d36fbfbd58c4a6a71d20088971dc
--- /dev/null
+++ b/quote_tool/app/blueprints/quotes.py
@@ -0,0 +1,61 @@
+"""Quote entry endpoints."""
+from __future__ import annotations
+
+import random
+from flask import Blueprint, jsonify, redirect, render_template, request, url_for
+from flask_login import current_user, login_required
+from wtforms import FieldList, Form, IntegerField, SelectField, StringField
+from wtforms.validators import DataRequired, Length
+
+from ..services.quote import QuoteRequest, persist_quote
+from ..models import Accessorial
+
+
+class QuoteForm(Form):
+    mode = SelectField("Mode", choices=[("hotshot", "Hotshot"), ("air", "Air")], validators=[DataRequired()])
+    origin_zip = StringField("Origin ZIP", validators=[DataRequired(), Length(min=3, max=10)])
+    destination_zip = StringField("Destination ZIP", validators=[DataRequired(), Length(min=3, max=10)])
+    weight_lbs = IntegerField("Weight (lbs)", validators=[DataRequired()])
+    length = IntegerField("Length", validators=[DataRequired()])
+    width = IntegerField("Width", validators=[DataRequired()])
+    height = IntegerField("Height", validators=[DataRequired()])
+
+
+bp = Blueprint("quotes", __name__, url_prefix="/quotes")
+
+
+@bp.route("/new", methods=["GET", "POST"])
+@login_required
+def new_quote():
+    form = QuoteForm(request.form)
+    accessorials = Accessorial.query.all()
+    if request.method == "POST" and form.validate():
+        req = QuoteRequest(
+            mode=form.mode.data,
+            origin_zip=form.origin_zip.data,
+            destination_zip=form.destination_zip.data,
+            weight_lbs=form.weight_lbs.data,
+            dimensions=(form.length.data, form.width.data, form.height.data),
+            accessorial_codes=request.form.getlist("accessorials"),
+        )
+        distance = random.uniform(50, 500)  # placeholder distance until API wiring added
+        quote = persist_quote(req, distance)
+        if request.accept_mimetypes.best == "application/json":
+            return jsonify(
+                {
+                    "id": quote.id,
+                    "grand_total": quote.grand_total,
+                    "billable_weight": quote.billable_weight,
+                }
+            )
+        return redirect(url_for("quotes.view_quote", quote_id=quote.id))
+    return render_template("new_quote.html", form=form, accessorials=accessorials)
+
+
+@bp.route("/<int:quote_id>")
+@login_required
+def view_quote(quote_id: int):
+    from ..models import Quote
+
+    quote = Quote.query.get_or_404(quote_id)
+    return render_template("quote_detail.html", quote=quote)
diff --git a/quote_tool/app/config.py b/quote_tool/app/config.py
new file mode 100644
index 0000000000000000000000000000000000000000..c0a5aac95db48f09813103f9986b42cd49637f53
--- /dev/null
+++ b/quote_tool/app/config.py
@@ -0,0 +1,32 @@
+"""Configuration defaults for Quote Tool.
+
+The class is intentionally small and environment-driven to make it easy to deploy
+in multiple environments. Production deployments should override any values with
+sensitive secrets using environment variables.
+"""
+from __future__ import annotations
+
+import os
+from datetime import timedelta
+
+
+class Config:
+    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
+    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///quote_tool.db")
+    SQLALCHEMY_TRACK_MODIFICATIONS = False
+    REMEMBER_COOKIE_DURATION = timedelta(days=14)
+    SESSION_PROTECTION = "strong"
+
+    # Mail configuration (stubbed for local development)
+    SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
+    SMTP_PORT = int(os.environ.get("SMTP_PORT", 1025))
+    SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
+    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
+    SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "false").lower() == "true"
+    GOOGLE_MAPS_API_KEY = os.environ.get("GOOGLE_MAPS_API_KEY", "")
+
+    # Rate limiting
+    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI")
+    RATELIMIT_HEADERS_ENABLED = True
+    RATELIMIT_DEFAULT = [os.environ.get("DAILY_LIMIT", "200 per day"), os.environ.get("HOURLY_LIMIT", "50 per hour")]
+    RATELIMIT_STRATEGY = "fixed-window"
diff --git a/quote_tool/app/models.py b/quote_tool/app/models.py
new file mode 100644
index 0000000000000000000000000000000000000000..61239ed6fa98b03b05c7db08a2d03208722b62ee
--- /dev/null
+++ b/quote_tool/app/models.py
@@ -0,0 +1,109 @@
+"""Database models for Quote Tool.
+
+These models capture a simplified structure mirroring the legacy application. They
+include users, quotes, accessorial charges, and rate tables for hotshot and air
+shipments.
+"""
+from __future__ import annotations
+
+from datetime import datetime
+from typing import Optional
+
+from flask_login import UserMixin
+from sqlalchemy import CheckConstraint, Column, Float, ForeignKey, Integer, String, Text, UniqueConstraint
+from sqlalchemy.orm import relationship
+
+from . import db, login_manager
+
+
+class User(db.Model, UserMixin):
+    id = Column(Integer, primary_key=True)
+    email = Column(String(255), unique=True, nullable=False)
+    password_hash = Column(String(255), nullable=False)
+    role = Column(String(50), default="user")  # user, staff, admin
+    is_active = Column(Integer, default=1)
+
+    quotes = relationship("Quote", back_populates="user", cascade="all, delete-orphan")
+
+    def get_id(self) -> str:
+        return str(self.id)
+
+
+@login_manager.user_loader
+def load_user(user_id: str) -> Optional[User]:
+    return User.query.get(int(user_id))
+
+
+class Quote(db.Model):
+    id = Column(Integer, primary_key=True)
+    created_at = Column(db.DateTime, default=datetime.utcnow, nullable=False)
+    mode = Column(String(10), nullable=False)  # hotshot or air
+    origin_zip = Column(String(10), nullable=False)
+    destination_zip = Column(String(10), nullable=False)
+    distance_miles = Column(Float, nullable=False, default=0.0)
+    weight_lbs = Column(Float, nullable=False)
+    dim_weight = Column(Float, nullable=False)
+    billable_weight = Column(Float, nullable=False)
+    linehaul = Column(Float, nullable=False)
+    accessorial_total = Column(Float, nullable=False)
+    grand_total = Column(Float, nullable=False)
+    detail_json = Column(Text, default="{}", nullable=False)
+
+    user_id = Column(Integer, ForeignKey("user.id"))
+    user = relationship("User", back_populates="quotes")
+
+
+class Accessorial(db.Model):
+    id = Column(Integer, primary_key=True)
+    code = Column(String(50), unique=True, nullable=False)
+    description = Column(String(255), nullable=False)
+    amount = Column(Float, nullable=False, default=0.0)
+
+
+class HotshotRate(db.Model):
+    __table_args__ = (UniqueConstraint("miles_min", "miles_max", name="uniq_hotshot_range"),)
+
+    id = Column(Integer, primary_key=True)
+    miles_min = Column(Integer, nullable=False)
+    miles_max = Column(Integer, nullable=False)
+    rate_per_mile = Column(Float, nullable=False)
+
+
+class BeyondRate(db.Model):
+    id = Column(Integer, primary_key=True)
+    zone = Column(String(10), unique=True, nullable=False)
+    surcharge = Column(Float, nullable=False, default=0.0)
+
+
+class AirCostZone(db.Model):
+    id = Column(Integer, primary_key=True)
+    zone = Column(String(10), unique=True, nullable=False)
+    cost_per_lb = Column(Float, nullable=False)
+
+
+class ZipZone(db.Model):
+    id = Column(Integer, primary_key=True)
+    zipcode = Column(String(10), unique=True, nullable=False)
+    dest_zone = Column(String(10), nullable=False)
+    is_beyond = Column(Integer, nullable=False, default=0)
+
+
+class CostZone(db.Model):
+    id = Column(Integer, primary_key=True)
+    origin_zone = Column(String(10), nullable=False)
+    dest_zone = Column(String(10), nullable=False)
+    minimum_charge = Column(Float, nullable=False)
+    __table_args__ = (UniqueConstraint("origin_zone", "dest_zone", name="uniq_cost_zone"),)
+    __mapper_args__ = {"eager_defaults": True}
+
+
+__all__ = [
+    "User",
+    "Quote",
+    "Accessorial",
+    "HotshotRate",
+    "BeyondRate",
+    "AirCostZone",
+    "ZipZone",
+    "CostZone",
+]
diff --git a/quote_tool/app/services/auth.py b/quote_tool/app/services/auth.py
new file mode 100644
index 0000000000000000000000000000000000000000..04a18b99cd66cbb3a7e0c80c1dd669bb2894138a
--- /dev/null
+++ b/quote_tool/app/services/auth.py
@@ -0,0 +1,47 @@
+"""Authentication utilities for Quote Tool."""
+from __future__ import annotations
+
+import secrets
+from dataclasses import dataclass
+from typing import Optional
+
+from werkzeug.security import check_password_hash, generate_password_hash
+
+from .. import db
+from ..models import User
+
+
+@dataclass
+class Token:
+    value: str
+
+
+def hash_password(password: str) -> str:
+    return generate_password_hash(password)
+
+
+def verify_password(hash_value: str, password: str) -> bool:
+    return check_password_hash(hash_value, password)
+
+
+def issue_reset_token() -> Token:
+    """Generate a simple token for password resets.
+
+    In a production system this should be persisted and include expiry metadata. The
+    simplified design keeps the surface small for this re-implementation.
+    """
+    return Token(value=secrets.token_urlsafe(24))
+
+
+def create_user(email: str, password: str, role: str = "user") -> User:
+    user = User(email=email, password_hash=hash_password(password), role=role)
+    db.session.add(user)
+    db.session.commit()
+    return user
+
+
+def authenticate(email: str, password: str) -> Optional[User]:
+    user = User.query.filter_by(email=email).first()
+    if user and verify_password(user.password_hash, password):
+        return user
+    return None
diff --git a/quote_tool/app/services/quote.py b/quote_tool/app/services/quote.py
new file mode 100644
index 0000000000000000000000000000000000000000..cc6c8b10ff755e0864b4f85e5365787b3d22d0d0
--- /dev/null
+++ b/quote_tool/app/services/quote.py
@@ -0,0 +1,114 @@
+"""Quote orchestration services.
+
+This module contains pure functions for pricing logic so they can be reused by
+HTTP handlers and tests alike.
+"""
+from __future__ import annotations
+
+import json
+from dataclasses import dataclass, field
+from typing import Iterable, List, Mapping
+
+from ..models import Accessorial, BeyondRate, HotshotRate, Quote, ZipZone, AirCostZone, CostZone
+from .. import db
+
+DIM_DIVISOR = 166  # Standard domestic air divisor
+
+
+@dataclass
+class QuoteRequest:
+    mode: str
+    origin_zip: str
+    destination_zip: str
+    weight_lbs: float
+    dimensions: tuple[int, int, int]
+    accessorial_codes: List[str] = field(default_factory=list)
+
+
+def dim_weight(length: int, width: int, height: int) -> float:
+    return round((length * width * height) / DIM_DIVISOR, 2)
+
+
+def billable_weight(actual_weight: float, dimmed: float) -> float:
+    return max(actual_weight, dimmed)
+
+
+def _hotshot_rate(distance_miles: float) -> float:
+    band = HotshotRate.query.filter(HotshotRate.miles_min <= distance_miles, HotshotRate.miles_max >= distance_miles).first()
+    if not band:
+        return 0.0
+    return band.rate_per_mile * distance_miles
+
+
+def _beyond_surcharge(dest_zone: str) -> float:
+    rate = BeyondRate.query.filter_by(zone=dest_zone).first()
+    return rate.surcharge if rate else 0.0
+
+
+def hotshot_quote(distance_miles: float, weight: float, dest_zone: str) -> float:
+    return round(_hotshot_rate(distance_miles) + _beyond_surcharge(dest_zone) + (0.15 * weight), 2)
+
+
+def _lookup_dest_zone(zipcode: str) -> ZipZone | None:
+    return ZipZone.query.filter_by(zipcode=zipcode).first()
+
+
+def air_quote(origin_zip: str, dest_zip: str, weight: float) -> float:
+    origin_zone = _lookup_dest_zone(origin_zip)
+    dest_zone = _lookup_dest_zone(dest_zip)
+    if not origin_zone or not dest_zone:
+        return 0.0
+    cost_zone = CostZone.query.filter_by(origin_zone=origin_zone.dest_zone, dest_zone=dest_zone.dest_zone).first()
+    air_rate = AirCostZone.query.filter_by(zone=dest_zone.dest_zone).first()
+    per_lb = air_rate.cost_per_lb if air_rate else 0.0
+    minimum = cost_zone.minimum_charge if cost_zone else 0.0
+    return round(max(per_lb * weight, minimum), 2)
+
+
+def guarantee_cost(weight: float, multiplier: float = 0.05) -> float:
+    return round(weight * multiplier, 2)
+
+
+def compute_accessorial_total(codes: Iterable[str]) -> float:
+    mapping = {acc.code: acc.amount for acc in Accessorial.query.filter(Accessorial.code.in_(list(codes))).all()}
+    return round(sum(mapping.get(code, 0.0) for code in codes), 2)
+
+
+def persist_quote(req: QuoteRequest, distance_miles: float) -> Quote:
+    dimmed = dim_weight(*req.dimensions)
+    billable = billable_weight(req.weight_lbs, dimmed)
+
+    dest_zone = _lookup_dest_zone(req.destination_zip)
+    dest_code = dest_zone.dest_zone if dest_zone else ""
+
+    if req.mode == "hotshot":
+        linehaul_total = hotshot_quote(distance_miles, billable, dest_code)
+    else:
+        linehaul_total = air_quote(req.origin_zip, req.destination_zip, billable)
+
+    acc_total = compute_accessorial_total(req.accessorial_codes)
+    grand_total = round(linehaul_total + acc_total + guarantee_cost(billable), 2)
+
+    quote = Quote(
+        mode=req.mode,
+        origin_zip=req.origin_zip,
+        destination_zip=req.destination_zip,
+        distance_miles=distance_miles,
+        weight_lbs=req.weight_lbs,
+        dim_weight=dimmed,
+        billable_weight=billable,
+        linehaul=linehaul_total,
+        accessorial_total=acc_total,
+        grand_total=grand_total,
+        detail_json=json.dumps(
+            {
+                "accessorials": req.accessorial_codes,
+                "dimensions": req.dimensions,
+                "distance_miles": distance_miles,
+            }
+        ),
+    )
+
+    db.session.add(quote)
+    db.session.commit()
+    return quote
diff --git a/quote_tool/app/templates/admin_dashboard.html b/quote_tool/app/templates/admin_dashboard.html
new file mode 100644
index 0000000000000000000000000000000000000000..52caac70b00a88dd394902f2497521abfcff1086
--- /dev/null
+++ b/quote_tool/app/templates/admin_dashboard.html
@@ -0,0 +1,5 @@
+{% extends "base.html" %}
+{% block content %}
+<h1>Admin Dashboard</h1>
+<p>This reimplementation includes placeholders for rate imports, user approvals, and history exports.</p>
+{% endblock %}
diff --git a/quote_tool/app/templates/base.html b/quote_tool/app/templates/base.html
new file mode 100644
index 0000000000000000000000000000000000000000..4bea301df7a78a681d0df35fb3d9c9a386e1e691
--- /dev/null
+++ b/quote_tool/app/templates/base.html
@@ -0,0 +1,25 @@
+<!doctype html>
+<html lang="en">
+  <head>
+    <meta charset="utf-8">
+    <title>Quote Tool</title>
+    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
+  </head>
+  <body class="container py-4">
+    <nav class="mb-4">
+      <a href="/quotes/new" class="me-2">New Quote</a>
+      <a href="/admin/" class="me-2">Admin</a>
+      <a href="/auth/logout" class="me-2">Logout</a>
+    </nav>
+    {% with messages = get_flashed_messages(with_categories=true) %}
+      {% if messages %}
+        <div>
+          {% for category, message in messages %}
+            <div class="alert alert-{{ category }}">{{ message }}</div>
+          {% endfor %}
+        </div>
+      {% endif %}
+    {% endwith %}
+    {% block content %}{% endblock %}
+  </body>
+</html>
diff --git a/quote_tool/app/templates/login.html b/quote_tool/app/templates/login.html
new file mode 100644
index 0000000000000000000000000000000000000000..07fe13e6eb162059682c200a552dd61bb84a362e
--- /dev/null
+++ b/quote_tool/app/templates/login.html
@@ -0,0 +1,10 @@
+{% extends "base.html" %}
+{% block content %}
+<h1>Login</h1>
+<form method="post">
+  <div class="mb-3"><label>Email <input type="email" name="email" class="form-control"></label></div>
+  <div class="mb-3"><label>Password <input type="password" name="password" class="form-control"></label></div>
+  <button class="btn btn-primary">Login</button>
+</form>
+<p><a href="{{ url_for('auth.register') }}">Register</a> | <a href="{{ url_for('auth.reset_password') }}">Reset password</a></p>
+{% endblock %}
diff --git a/quote_tool/app/templates/new_quote.html b/quote_tool/app/templates/new_quote.html
new file mode 100644
index 0000000000000000000000000000000000000000..b909013075493fe006866dd05e251896ed9256ad
--- /dev/null
+++ b/quote_tool/app/templates/new_quote.html
@@ -0,0 +1,27 @@
+{% extends "base.html" %}
+{% block content %}
+<h1>New Quote</h1>
+<form method="post">
+  <div class="row mb-3">
+    <div class="col"><label>Mode <select name="mode" class="form-select"><option value="hotshot">Hotshot</option><option value="air">Air</option></select></label></div>
+    <div class="col"><label>Origin ZIP <input type="text" name="origin_zip" class="form-control"></label></div>
+    <div class="col"><label>Destination ZIP <input type="text" name="destination_zip" class="form-control"></label></div>
+  </div>
+  <div class="row mb-3">
+    <div class="col"><label>Weight (lbs) <input type="number" name="weight_lbs" class="form-control"></label></div>
+    <div class="col"><label>Length <input type="number" name="length" class="form-control"></label></div>
+    <div class="col"><label>Width <input type="number" name="width" class="form-control"></label></div>
+    <div class="col"><label>Height <input type="number" name="height" class="form-control"></label></div>
+  </div>
+  <div class="mb-3">
+    <strong>Accessorials</strong>
+    {% for acc in accessorials %}
+      <div class="form-check">
+        <input class="form-check-input" type="checkbox" name="accessorials" value="{{ acc.code }}" id="acc-{{ acc.id }}">
+        <label class="form-check-label" for="acc-{{ acc.id }}">{{ acc.description }} (${{ acc.amount }})</label>
+      </div>
+    {% endfor %}
+  </div>
+  <button class="btn btn-primary">Price</button>
+</form>
+{% endblock %}
diff --git a/quote_tool/app/templates/quote_detail.html b/quote_tool/app/templates/quote_detail.html
new file mode 100644
index 0000000000000000000000000000000000000000..ed7a54d943a1a665c16d1fcc83e59632df6aeee0
--- /dev/null
+++ b/quote_tool/app/templates/quote_detail.html
@@ -0,0 +1,14 @@
+{% extends "base.html" %}
+{% block content %}
+<h1>Quote #{{ quote.id }}</h1>
+<ul>
+  <li>Mode: {{ quote.mode }}</li>
+  <li>From {{ quote.origin_zip }} to {{ quote.destination_zip }}</li>
+  <li>Distance: {{ quote.distance_miles }} miles</li>
+  <li>Billable weight: {{ quote.billable_weight }} lbs</li>
+  <li>Linehaul: ${{ quote.linehaul }}</li>
+  <li>Accessorials: ${{ quote.accessorial_total }}</li>
+  <li>Guarantee + misc included in total</li>
+  <li>Total: ${{ quote.grand_total }}</li>
+</ul>
+{% endblock %}
diff --git a/quote_tool/app/templates/register.html b/quote_tool/app/templates/register.html
new file mode 100644
index 0000000000000000000000000000000000000000..e8aaef76a672b588e94a71dab6a93a18ef35c8c5
--- /dev/null
+++ b/quote_tool/app/templates/register.html
@@ -0,0 +1,10 @@
+{% extends "base.html" %}
+{% block content %}
+<h1>Register</h1>
+<form method="post">
+  <div class="mb-3"><label>Email <input type="email" name="email" class="form-control"></label></div>
+  <div class="mb-3"><label>Password <input type="password" name="password" class="form-control"></label></div>
+  <button class="btn btn-primary">Create account</button>
+</form>
+<p><a href="{{ url_for('auth.login') }}">Back to login</a></p>
+{% endblock %}
diff --git a/quote_tool/app/templates/reset.html b/quote_tool/app/templates/reset.html
new file mode 100644
index 0000000000000000000000000000000000000000..e38251e4dc71c85665f088597f25d183e6bd49b2
--- /dev/null
+++ b/quote_tool/app/templates/reset.html
@@ -0,0 +1,11 @@
+{% extends "base.html" %}
+{% block content %}
+<h1>Reset Password</h1>
+<form method="post">
+  <div class="mb-3"><label>Email <input type="email" name="email" class="form-control"></label></div>
+  <button class="btn btn-primary">Issue token</button>
+</form>
+{% if token %}
+<div class="alert alert-info mt-3">Generated token: {{ token.value }}</div>
+{% endif %}
+{% endblock %}
diff --git a/requirements.txt b/requirements.txt
index f2aa2b6701f4816353ad4ffca8ca7177be3dd58f..ac92f377ad9dc04c0d35f2bdfda410a81efc79e4 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,3 +1,7 @@
-# Dependencies for the toolbelt scripts
-# mass_print.py relies only on the Python standard library on Windows.
-qrcode[pil]>=7.4
+Flask>=2.2
+Flask-SQLAlchemy>=3.0
+Flask-WTF>=1.1
+WTForms>=3.0
+Flask-Login>=0.6
+Flask-Limiter>=3.3
+pytest>=7.0
diff --git a/tests/test_quote_logic.py b/tests/test_quote_logic.py
new file mode 100644
index 0000000000000000000000000000000000000000..8945b37fe34f155f7947ac1a0cdd4966d3c6ad33
--- /dev/null
+++ b/tests/test_quote_logic.py
@@ -0,0 +1,82 @@
+import sys
+from pathlib import Path
+
+import pytest
+
+ROOT = Path(__file__).resolve().parents[1]
+sys.path.insert(0, str(ROOT))
+
+from quote_tool.app import create_app, db
+from quote_tool.app.models import Accessorial, AirCostZone, BeyondRate, CostZone, HotshotRate, User, ZipZone
+from quote_tool.app.services.quote import (
+    QuoteRequest,
+    air_quote,
+    billable_weight,
+    compute_accessorial_total,
+    dim_weight,
+    guarantee_cost,
+    hotshot_quote,
+    persist_quote,
+)
+
+
+@pytest.fixture()
+def app():
+    app = create_app({"SQLALCHEMY_DATABASE_URI": "sqlite://", "TESTING": True, "WTF_CSRF_ENABLED": False})
+    with app.app_context():
+        db.create_all()
+    yield app
+
+
+@pytest.fixture(autouse=True)
+def setup_rates(app):
+    with app.app_context():
+        db.session.add(HotshotRate(miles_min=0, miles_max=500, rate_per_mile=2.5))
+        db.session.add(BeyondRate(zone="B1", surcharge=150))
+        db.session.add(AirCostZone(zone="Z1", cost_per_lb=1.5))
+        db.session.add(CostZone(origin_zone="Z1", dest_zone="Z1", minimum_charge=200))
+        db.session.add(ZipZone(zipcode="77001", dest_zone="Z1", is_beyond=0))
+        db.session.add(ZipZone(zipcode="60601", dest_zone="B1", is_beyond=1))
+        db.session.add(Accessorial(code="LIFTGATE", description="Liftgate", amount=75))
+        db.session.commit()
+    yield
+
+
+def test_dim_and_billable():
+    assert dim_weight(48, 40, 40) == pytest.approx((48 * 40 * 40) / 166, rel=1e-3)
+    assert billable_weight(500, 700) == 700
+    assert billable_weight(900, 700) == 900
+
+
+def test_hotshot_quote(app):
+    with app.app_context():
+        total = hotshot_quote(100, 500, "B1")
+        assert total == round((2.5 * 100) + 150 + (0.15 * 500), 2)
+
+
+def test_air_quote(app):
+    with app.app_context():
+        total = air_quote("77001", "60601", 100)
+        assert total == 200  # minimum charge applies
+
+
+def test_accessorials(app):
+    with app.app_context():
+        assert compute_accessorial_total(["LIFTGATE", "UNKNOWN"]) == 75
+
+
+def test_persist_quote(app):
+    with app.app_context():
+        user = User(email="user@example.com", password_hash="x")
+        db.session.add(user)
+        db.session.commit()
+        req = QuoteRequest(
+            mode="hotshot",
+            origin_zip="77001",
+            destination_zip="60601",
+            weight_lbs=500,
+            dimensions=(48, 40, 40),
+            accessorial_codes=["LIFTGATE"],
+        )
+        quote = persist_quote(req, distance_miles=120)
+        assert quote.grand_total > 0
 
EOF
)
