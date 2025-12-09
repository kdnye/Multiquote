"""Quoting logic and orchestration."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from .. import db
from ..models import Accessorial, AirCostZone, BeyondRate, CostZone, HotshotRate, Quote, User, ZipZone


@dataclass
class QuoteRequest:
    mode: str
    origin_zip: str
    destination_zip: str
    weight_lbs: float
    dimensions: tuple[float, float, float] | None = None
    accessorial_codes: Sequence[str] | None = None


def dim_weight(length_in: float, width_in: float, height_in: float) -> float:
    return (length_in * width_in * height_in) / 166


def billable_weight(actual_weight: float, dimmed_weight: float) -> float:
    return max(actual_weight, dimmed_weight)


def guarantee_cost(minimum_charge: float, computed: float) -> float:
    return max(minimum_charge, round(computed, 2))


def _find_hotshot_rate(distance_miles: float) -> HotshotRate | None:
    for rate in HotshotRate.query.all():
        if rate.matches(distance_miles):
            return rate
    return None


def hotshot_quote(distance_miles: float, weight_lbs: float, beyond_zone: str | None) -> float:
    rate = _find_hotshot_rate(distance_miles)
    if not rate:
        raise ValueError("No hotshot rate available for distance")
    linehaul = distance_miles * rate.rate_per_mile
    surcharge = 0
    if beyond_zone:
        beyond = BeyondRate.query.filter_by(zone=beyond_zone).first()
        surcharge = beyond.surcharge if beyond else 0
    fuel = 0.15 * weight_lbs
    return round(linehaul + surcharge + fuel, 2)


def _lookup_zone(zipcode: str) -> ZipZone | None:
    return ZipZone.query.filter_by(zipcode=zipcode).first()


def air_quote(origin_zip: str, dest_zip: str, billable_lbs: float) -> float:
    origin_zone = _lookup_zone(origin_zip)
    dest_zone = _lookup_zone(dest_zip)
    if not origin_zone or not dest_zone:
        raise ValueError("Missing zone mapping for ZIP")

    cost_zone = CostZone.query.filter_by(origin_zone=origin_zone.dest_zone, dest_zone=dest_zone.dest_zone).first()
    matched_dest_zone = cost_zone is not None
    if not cost_zone and dest_zone.is_beyond:
        # Fallback to the base destination zone when beyond charges are handled separately.
        cost_zone = CostZone.query.filter_by(origin_zone=origin_zone.dest_zone, dest_zone=origin_zone.dest_zone).first()
    if not cost_zone:
        raise ValueError("Missing cost zone pair")

    air_cost = AirCostZone.query.filter_by(zone=origin_zone.dest_zone).first()
    if not air_cost:
        raise ValueError("Missing air cost zone")

    base = air_cost.cost_per_lb * billable_lbs
    total = guarantee_cost(cost_zone.minimum_charge, base)

    if dest_zone.is_beyond and matched_dest_zone:
        beyond = BeyondRate.query.filter_by(zone=dest_zone.dest_zone).first()
        if beyond:
            total += beyond.surcharge
    return round(total, 2)


def compute_accessorial_total(codes: Iterable[str]) -> float:
    total = 0.0
    for code in codes:
        accessorial = Accessorial.query.filter_by(code=code).first()
        if accessorial:
            total += accessorial.amount
    return round(total, 2)


def persist_quote(request: QuoteRequest, distance_miles: float | None = None, user: User | None = None) -> Quote:
    length = width = height = None
    dimmed = request.weight_lbs
    if request.dimensions:
        length, width, height = request.dimensions
        dimmed = dim_weight(length, width, height)
    billable = billable_weight(request.weight_lbs, dimmed)

    accessorial_codes = list(request.accessorial_codes or [])
    accessorial_total = compute_accessorial_total(accessorial_codes)

    grand_total = 0.0
    linehaul_total = 0.0
    fuel_surcharge = 0.0

    if request.mode == "hotshot":
        if distance_miles is None:
            raise ValueError("Distance required for hotshot quotes")
        beyond_zone = None
        dest_zone = _lookup_zone(request.destination_zip)
        if dest_zone and dest_zone.is_beyond:
            beyond_zone = dest_zone.dest_zone
        grand_total = hotshot_quote(distance_miles, billable, beyond_zone)
        linehaul_total = grand_total - accessorial_total
    else:
        grand_total = air_quote(request.origin_zip, request.destination_zip, billable)
        linehaul_total = grand_total - accessorial_total

    grand_total += accessorial_total

    quote = Quote(
        mode=request.mode,
        origin_zip=request.origin_zip,
        destination_zip=request.destination_zip,
        weight_lbs=request.weight_lbs,
        length_in=length,
        width_in=width,
        height_in=height,
        distance_miles=distance_miles,
        billable_weight=billable,
        accessorial_codes=",".join(accessorial_codes),
        linehaul_total=linehaul_total,
        fuel_surcharge=fuel_surcharge,
        accessorial_total=accessorial_total,
        grand_total=round(grand_total, 2),
        user=user,
    )
    db.session.add(quote)
    db.session.commit()
    return quote
