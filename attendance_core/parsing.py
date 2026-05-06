def parse_positive_int(value, default):
    try:
        parsed = int(str(value).strip())
        return parsed if parsed > 0 else default
    except Exception:
        return default


def parse_non_negative_int(value, default):
    try:
        parsed = int(str(value).strip())
        return parsed if parsed >= 0 else default
    except Exception:
        return default


def parse_money_value(value, default=0.0):
    try:
        cleaned = str(value).strip().replace(",", "")
        if cleaned == "":
            return default
        parsed = round(float(cleaned), 2)
        return parsed if parsed >= 0 else default
    except Exception:
        return default


def paginate_items(items, page, page_size):
    total = len(items)
    page_size = page_size if page_size in {10, 25, 50, 100} else 25
    total_pages = max((total + page_size - 1) // page_size, 1)
    page = max(min(page, total_pages), 1)
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "items": items[start:end],
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
        "start_index": start + 1 if total else 0,
        "end_index": min(end, total),
        "has_prev": page > 1,
        "has_next": page < total_pages,
    }
