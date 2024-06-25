from datetime import datetime, date, timezone


def difference_seconds(start: datetime, end: datetime) -> float:
    """Returns the difference in seconds between two datetimes"""
    return abs((end - start).total_seconds())


def utc_now() -> datetime:
    """Returns the current datetime with tz info in UTC."""
    return datetime.now(timezone.utc)


def iso_now() -> str:
    """Returns the current timestamp in iso8601"""
    return utc_now().isoformat()


def today() -> date:
    """Returns the current date"""
    return utc_now().date()
