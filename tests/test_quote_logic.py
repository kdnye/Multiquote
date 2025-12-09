import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from quote_tool.app import create_app, db
from quote_tool.app.models import Accessorial, AirCostZone, BeyondRate, CostZone, HotshotRate, User, ZipZone
from quote_tool.app.services.quote import (
    QuoteRequest,
    air_quote,
    billable_weight,
    compute_accessorial_total,
    dim_weight,
    guarantee_cost,
    hotshot_quote,
    persist_quote,
)


@pytest.fixture()
def app():
    app = create_app({"SQLALCHEMY_DATABASE_URI": "sqlite://", "TESTING": True, "WTF_CSRF_ENABLED": False, "RATELIMIT_ENABLED": False})
    with app.app_context():
        db.create_all()
    yield app


@pytest.fixture(autouse=True)
def setup_rates(app):
    with app.app_context():
        db.session.add(HotshotRate(miles_min=0, miles_max=500, rate_per_mile=2.5))
        db.session.add(BeyondRate(zone="B1", surcharge=150))
        db.session.add(AirCostZone(zone="Z1", cost_per_lb=1.5))
        db.session.add(CostZone(origin_zone="Z1", dest_zone="Z1", minimum_charge=200))
        db.session.add(ZipZone(zipcode="77001", dest_zone="Z1", is_beyond=0))
        db.session.add(ZipZone(zipcode="60601", dest_zone="B1", is_beyond=1))
        db.session.add(Accessorial(code="LIFTGATE", description="Liftgate", amount=75))
        db.session.commit()
    yield


def test_dim_and_billable():
    assert dim_weight(48, 40, 40) == pytest.approx((48 * 40 * 40) / 166, rel=1e-3)
    assert billable_weight(500, 700) == 700
    assert billable_weight(900, 700) == 900


def test_hotshot_quote(app):
    with app.app_context():
        total = hotshot_quote(100, 500, "B1")
        assert total == round((2.5 * 100) + 150 + (0.15 * 500), 2)


def test_air_quote(app):
    with app.app_context():
        total = air_quote("77001", "60601", 100)
        assert total == 200


def test_accessorials(app):
    with app.app_context():
        assert compute_accessorial_total(["LIFTGATE", "UNKNOWN"]) == 75


def test_persist_quote(app):
    with app.app_context():
        user = User(email="user@example.com", password_hash="x")
        db.session.add(user)
        db.session.commit()
        req = QuoteRequest(
            mode="hotshot",
            origin_zip="77001",
            destination_zip="60601",
            weight_lbs=500,
            dimensions=(48, 40, 40),
            accessorial_codes=["LIFTGATE"],
        )
        quote = persist_quote(req, distance_miles=120, user=user)
        assert quote.grand_total > 0
