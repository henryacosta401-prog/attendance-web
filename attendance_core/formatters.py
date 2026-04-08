def minutes_to_hm(minutes):
    minutes = int(minutes or 0)
    h = minutes // 60
    m = minutes % 60
    return f"{h}h {m}m"


def minutes_to_decimal_hours(minutes):
    return round((minutes or 0) / 60, 2)


def format_currency(value):
    try:
        return f"PHP {float(value or 0):,.2f}"
    except Exception:
        return "PHP 0.00"
