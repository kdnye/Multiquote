"""Administrative dashboards."""
from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from .. import db
from ..models import Accessorial, AirCostZone, BeyondRate, CostZone, HotshotRate, User, ZipZone

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _require_admin():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)


@bp.route("/")
@login_required
def dashboard():
    _require_admin()
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/dashboard.html", users=users)


@bp.route("/rates", methods=["GET", "POST"])
@login_required
def rates():
    _require_admin()
    if request.method == "POST":
        rate_type = request.form.get("type")
        if rate_type == "hotshot":
            rate = HotshotRate(
                miles_min=int(request.form.get("miles_min", 0)),
                miles_max=int(request.form.get("miles_max", 0)),
                rate_per_mile=float(request.form.get("rate_per_mile", 0)),
            )
            db.session.add(rate)
        elif rate_type == "beyond":
            db.session.add(BeyondRate(zone=request.form.get("zone"), surcharge=float(request.form.get("surcharge", 0))))
        elif rate_type == "aircost":
            db.session.add(AirCostZone(zone=request.form.get("zone"), cost_per_lb=float(request.form.get("cost_per_lb", 0))))
        elif rate_type == "zipzone":
            db.session.add(
                ZipZone(
                    zipcode=request.form.get("zipcode"),
                    dest_zone=request.form.get("dest_zone"),
                    is_beyond=bool(int(request.form.get("is_beyond", 0))),
                )
            )
        elif rate_type == "costzone":
            db.session.add(
                CostZone(
                    origin_zone=request.form.get("origin_zone"),
                    dest_zone=request.form.get("dest_zone"),
                    minimum_charge=float(request.form.get("minimum_charge", 0)),
                )
            )
        db.session.commit()
        flash("Rate saved", "success")
        return redirect(url_for("admin.rates"))

    context = {
        "hotshot_rates": HotshotRate.query.all(),
        "beyond_rates": BeyondRate.query.all(),
        "air_cost_zones": AirCostZone.query.all(),
        "zip_zones": ZipZone.query.all(),
        "cost_zones": CostZone.query.all(),
    }
    return render_template("admin/rates.html", **context)
