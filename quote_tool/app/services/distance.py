"""Distance lookup service using Google Maps Directions API."""
from __future__ import annotations

import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

GOOGLE_MAPS_ENDPOINT = "https://maps.googleapis.com/maps/api/directions/json"


def fetch_distance(origin_zip: str, dest_zip: str, api_key: str | None, retries: int = 3) -> Optional[float]:
    """Fetch driving distance in miles between two ZIP codes using Google Maps.

    Args:
        origin_zip: Origin postal code.
        dest_zip: Destination postal code.
        api_key: Google Maps API key; when missing, the function returns ``None``
            to allow offline calculations during development.
        retries: Number of attempts before giving up.

    Returns:
        Distance in miles if available, otherwise ``None``.
    """
    if not api_key:
        logger.warning("GOOGLE_MAPS_API_KEY not configured; skipping distance lookup")
        return None

    params = {"origin": origin_zip, "destination": dest_zip, "key": api_key, "mode": "driving"}
    for attempt in range(retries):
        try:
            response = requests.get(GOOGLE_MAPS_ENDPOINT, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data.get("routes"):
                meters = data["routes"][0]["legs"][0]["distance"]["value"]
                return round(meters / 1609.34, 2)
            logger.error("No routes returned from Google Maps: %s", data)
        except requests.RequestException as exc:  # pragma: no cover - network issues
            logger.error("Distance lookup failed (attempt %s/%s): %s", attempt + 1, retries, exc)
    return None
