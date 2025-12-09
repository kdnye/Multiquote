"""Lightweight application factory with in-memory persistence."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional, Type, TypeVar

from .config import Config

T = TypeVar("T")


class SimpleQuery:
    """Minimal query helper over an in-memory store."""

    def __init__(self, db: "SimpleDB", model: Type[T], seed: Optional[List[T]] = None):
        self.db = db
        self.model = model
        self._data = seed

    def _records(self) -> List[T]:
        if self._data is not None:
            return list(self._data)
        return list(self.db._records.get(self.model, []))

    def filter_by(self, **kwargs: Any) -> "SimpleQuery":
        data = [obj for obj in self._records() if all(getattr(obj, k, None) == v for k, v in kwargs.items())]
        return SimpleQuery(self.db, self.model, data)

    def first(self) -> Optional[T]:
        records = self._records()
        return records[0] if records else None

    def all(self) -> List[T]:
        return self._records()

    def get(self, identity: int) -> Optional[T]:
        return next((obj for obj in self._records() if getattr(obj, "id", None) == identity), None)


class QueryDescriptor:
    """Descriptor exposing ``Model.query`` akin to SQLAlchemy."""

    def __init__(self, db: "SimpleDB"):
        self.db = db

    def __get__(self, instance: Any, owner: Type[T]) -> SimpleQuery:  # pragma: no cover - trivial
        return SimpleQuery(self.db, owner)


class SimpleSession:
    def __init__(self, db: "SimpleDB"):
        self.db = db

    def add(self, obj: Any) -> None:
        records = self.db._records.setdefault(type(obj), [])
        if getattr(obj, "id", None) is None and hasattr(obj, "id"):
            obj.id = len(records) + 1
        records.append(obj)
        if getattr(obj, "user", None) is not None and hasattr(obj.user, "quotes"):
            obj.user.quotes.append(obj)

    def commit(self) -> None:  # pragma: no cover - included for API compatibility
        return None


class SimpleDB:
    """Tiny in-memory stand-in for SQLAlchemy."""

    def __init__(self) -> None:
        self._records: Dict[Type[Any], List[Any]] = {}
        self.session = SimpleSession(self)
        self.Model = self._build_model_base()

    def _build_model_base(self) -> Type[Any]:
        db = self

        class Model:
            query: SimpleQuery = QueryDescriptor(db)

            def __init__(self, **kwargs: Any) -> None:
                for key, value in kwargs.items():
                    setattr(self, key, value)

        return Model

    def create_all(self) -> None:  # pragma: no cover - maintained for API parity
        return None

    def drop_all(self) -> None:  # pragma: no cover
        self._records.clear()


class SimpleApp:
    """Lightweight stand-in for a Flask application."""

    def __init__(self, base_config: Optional[Dict[str, Any]] = None) -> None:
        self.config: Dict[str, Any] = base_config or {}

    @contextmanager
    def app_context(self) -> Iterable["SimpleApp"]:
        yield self

    def run(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover - convenience for parity
        print("Running simple app with config:", self.config)


db = SimpleDB()


def create_app(config_overrides: Dict[str, Any] | None = None) -> SimpleApp:
    """Create a simple application backed by the in-memory database."""

    app = SimpleApp(Config.as_dict())
    if config_overrides:
        app.config.update(config_overrides)

    # Ensure models are imported so they register with the db descriptor
    from . import models  # noqa: F401

    with app.app_context():
        db.create_all()

    return app
