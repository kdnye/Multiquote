"""Application factory for Quote Tool."""
from __future__ import annotations

from typing import Any, Dict

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from .config import Config

csrf = CSRFProtect()
db = SQLAlchemy()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])


def create_app(config_overrides: Dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True, template_folder="templates")
    app.config.from_object(Config)
    if config_overrides:
        app.config.update(config_overrides)

    csrf.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    if app.config.get("RATELIMIT_ENABLED", True):
        limiter.init_app(app)
    else:
        limiter.enabled = False

    from .models import User

    @login_manager.user_loader
    def load_user(user_id: str) -> User | None:
        return User.query.get(int(user_id))

    from .blueprints.auth import bp as auth_bp
    from .blueprints.quotes import bp as quotes_bp
    from .blueprints.admin import bp as admin_bp
    from .blueprints.help import bp as help_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(quotes_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(help_bp)

    with app.app_context():
        db.create_all()

    return app
