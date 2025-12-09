"""Database models for Quote Tool."""
from __future__ import annotations

from datetime import datetime
from typing import List

from . import db


class UserMixin:
    """Tiny stand-in for :class:`flask_login.UserMixin`."""

    @property
    def is_authenticated(self) -> bool:  # pragma: no cover - compatibility only
        return True

    @property
    def is_active(self) -> bool:  # pragma: no cover
        return True

    @property
    def is_anonymous(self) -> bool:  # pragma: no cover
        return False

    def get_id(self) -> str:  # pragma: no cover
        return str(getattr(self, "id", ""))


class User(UserMixin, db.Model):
    def __init__(
        self,
        email: str,
        password_hash: str,
        is_admin: bool = False,
        is_staff: bool = False,
        can_send_mail: bool = False,
        created_at: datetime | None = None,
    ) -> None:
        super().__init__(
            id=None,
            email=email,
            password_hash=password_hash,
            is_admin=is_admin,
            is_staff=is_staff,
            can_send_mail=can_send_mail,
            created_at=created_at or datetime.utcnow(),
        )
        self.quotes: List[Quote] = []

    def set_password(self, password: str) -> None:
        self.password_hash = password

    def check_password(self, password: str) -> bool:
        return self.password_hash == password


class Quote(db.Model):
    def __init__(
        self,
        mode: str,
        origin_zip: str,
        destination_zip: str,
        weight_lbs: float,
        length_in: float | None = None,
        width_in: float | None = None,
        height_in: float | None = None,
        distance_miles: float | None = None,
        billable_weight: float | None = None,
        accessorial_codes: str = "",
        linehaul_total: float = 0.0,
        fuel_surcharge: float = 0.0,
        accessorial_total: float = 0.0,
        grand_total: float = 0.0,
        created_at: datetime | None = None,
        user: User | None = None,
    ) -> None:
        super().__init__(
            id=None,
            mode=mode,
            origin_zip=origin_zip,
            destination_zip=destination_zip,
            weight_lbs=weight_lbs,
            length_in=length_in,
            width_in=width_in,
            height_in=height_in,
            distance_miles=distance_miles,
            billable_weight=billable_weight,
            accessorial_codes=accessorial_codes,
            linehaul_total=linehaul_total,
            fuel_surcharge=fuel_surcharge,
            accessorial_total=accessorial_total,
            grand_total=grand_total,
            created_at=created_at or datetime.utcnow(),
            user=user,
        )


class EmailQuoteRequest(db.Model):
    def __init__(
        self,
        quote_id: int,
        recipient: str,
        type: str,
        sent_at: datetime | None = None,
        status: str = "pending",
    ) -> None:
        super().__init__(
            id=None,
            quote_id=quote_id,
            recipient=recipient,
            type=type,
            sent_at=sent_at or datetime.utcnow(),
            status=status,
        )


class Accessorial(db.Model):
    def __init__(self, code: str, description: str, amount: float) -> None:
        super().__init__(code=code, description=description, amount=amount)


class HotshotRate(db.Model):
    def __init__(self, miles_min: int, miles_max: int, rate_per_mile: float) -> None:
        super().__init__(id=None, miles_min=miles_min, miles_max=miles_max, rate_per_mile=rate_per_mile)

    def matches(self, distance: float) -> bool:
        return self.miles_min <= distance <= self.miles_max


class BeyondRate(db.Model):
    def __init__(self, zone: str, surcharge: float) -> None:
        super().__init__(id=None, zone=zone, surcharge=surcharge)


class AirCostZone(db.Model):
    def __init__(self, zone: str, cost_per_lb: float) -> None:
        super().__init__(id=None, zone=zone, cost_per_lb=cost_per_lb)


class ZipZone(db.Model):
    def __init__(self, zipcode: str, dest_zone: str, is_beyond: bool = False) -> None:
        super().__init__(id=None, zipcode=zipcode, dest_zone=dest_zone, is_beyond=is_beyond)


class CostZone(db.Model):
    def __init__(self, origin_zone: str, dest_zone: str, minimum_charge: float) -> None:
        super().__init__(id=None, origin_zone=origin_zone, dest_zone=dest_zone, minimum_charge=minimum_charge)
