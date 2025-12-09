"""Database models for Quote Tool."""
from __future__ import annotations

from datetime import datetime
from typing import List

from flask_login import UserMixin
from sqlalchemy import UniqueConstraint
from werkzeug.security import check_password_hash, generate_password_hash

from . import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_staff = db.Column(db.Boolean, default=False)
    can_send_mail = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    quotes = db.relationship("Quote", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Quote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mode = db.Column(db.String(20), nullable=False)
    origin_zip = db.Column(db.String(20), nullable=False)
    destination_zip = db.Column(db.String(20), nullable=False)
    weight_lbs = db.Column(db.Float, nullable=False)
    length_in = db.Column(db.Float, nullable=True)
    width_in = db.Column(db.Float, nullable=True)
    height_in = db.Column(db.Float, nullable=True)
    distance_miles = db.Column(db.Float, nullable=True)
    billable_weight = db.Column(db.Float, nullable=True)
    accessorial_codes = db.Column(db.String(255), default="")
    linehaul_total = db.Column(db.Float, default=0)
    fuel_surcharge = db.Column(db.Float, default=0)
    accessorial_total = db.Column(db.Float, default=0)
    grand_total = db.Column(db.Float, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship("User", back_populates="quotes")


class EmailQuoteRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quote_id = db.Column(db.Integer, db.ForeignKey("quote.id"), nullable=False)
    recipient = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="pending")

    quote = db.relationship("Quote")


class Accessorial(db.Model):
    code = db.Column(db.String(50), primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Float, nullable=False)


class HotshotRate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    miles_min = db.Column(db.Integer, nullable=False)
    miles_max = db.Column(db.Integer, nullable=False)
    rate_per_mile = db.Column(db.Float, nullable=False)

    def matches(self, distance: float) -> bool:
        return self.miles_min <= distance <= self.miles_max


class BeyondRate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    zone = db.Column(db.String(50), unique=True, nullable=False)
    surcharge = db.Column(db.Float, nullable=False)


class AirCostZone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    zone = db.Column(db.String(50), unique=True, nullable=False)
    cost_per_lb = db.Column(db.Float, nullable=False)


class ZipZone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    zipcode = db.Column(db.String(20), unique=True, nullable=False)
    dest_zone = db.Column(db.String(50), nullable=False)
    is_beyond = db.Column(db.Boolean, default=False)


class CostZone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    origin_zone = db.Column(db.String(50), nullable=False)
    dest_zone = db.Column(db.String(50), nullable=False)
    minimum_charge = db.Column(db.Float, nullable=False)

    __table_args__ = (UniqueConstraint("origin_zone", "dest_zone", name="uq_cost_zone_pair"),)
