"""Help pages."""
from __future__ import annotations

from flask import Blueprint, render_template

bp = Blueprint("help", __name__)


@bp.route("/")
def index():
    return render_template("index.html")
