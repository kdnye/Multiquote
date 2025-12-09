"""Quote endpoints."""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import current_user, login_required

from ..forms import QuoteForm
from ..models import Accessorial, Quote
from ..services.distance import fetch_distance
from ..services.quote import QuoteRequest, persist_quote

bp = Blueprint("quotes", __name__, url_prefix="/quotes")


@bp.route("/new", methods=["GET", "POST"])
@login_required
def new_quote():
    form = QuoteForm()
    if request.is_json:
        payload = request.get_json() or {}
        distance = payload.get("distance_miles")
        qr = QuoteRequest(
            mode=payload.get("mode", "hotshot"),
            origin_zip=payload.get("origin_zip", ""),
            destination_zip=payload.get("destination_zip", ""),
            weight_lbs=float(payload.get("weight_lbs", 0)),
            dimensions=tuple(payload.get("dimensions", [])) or None,
            accessorial_codes=payload.get("accessorials", []),
        )
        quote = persist_quote(qr, distance_miles=distance, user=current_user)
        return jsonify({"id": quote.id, "grand_total": quote.grand_total})

    quote = None
    if form.validate_on_submit():
        accessorials = [c.strip() for c in (form.accessorials.data or "").split(",") if c.strip()]
        distance = None
        if form.mode.data == "hotshot":
            distance = fetch_distance(
                form.origin_zip.data, form.destination_zip.data, current_app.config.get("GOOGLE_MAPS_API_KEY")
            )
            if distance is None:
                distance = 0
        qr = QuoteRequest(
            mode=form.mode.data,
            origin_zip=form.origin_zip.data,
            destination_zip=form.destination_zip.data,
            weight_lbs=form.weight_lbs.data,
            dimensions=(form.length_in.data or 0, form.width_in.data or 0, form.height_in.data or 0)
            if form.length_in.data and form.width_in.data and form.height_in.data
            else None,
            accessorial_codes=accessorials,
        )
        quote = persist_quote(qr, distance_miles=distance, user=current_user)
    accessorials = Accessorial.query.order_by(Accessorial.code).all()
    return render_template("quote_form.html", form=form, quote=quote, accessorials=accessorials)


@bp.route("/history")
@login_required
def history():
    quotes = Quote.query.filter_by(user_id=current_user.id).order_by(Quote.created_at.desc()).all()
    return render_template("quote_history.html", quotes=quotes)
