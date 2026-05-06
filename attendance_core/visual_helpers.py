from urllib.parse import quote


def get_avatar_initials(name):
    parts = [part.strip() for part in (name or "").split() if part.strip()]
    if not parts:
        return "U"
    initials = "".join(part[0] for part in parts[:2]).upper()
    return initials or "U"


CODE128_PATTERNS = [
    "212222", "222122", "222221", "121223", "121322", "131222", "122213", "122312", "132212", "221213",
    "221312", "231212", "112232", "122132", "122231", "113222", "123122", "123221", "223211", "221132",
    "221231", "213212", "223112", "312131", "311222", "321122", "321221", "312212", "322112", "322211",
    "212123", "212321", "232121", "111323", "131123", "131321", "112313", "132113", "132311", "211313",
    "231113", "231311", "112133", "112331", "132131", "113123", "113321", "133121", "313121", "211331",
    "231131", "213113", "213311", "213131", "311123", "311321", "331121", "312113", "312311", "332111",
    "314111", "221411", "431111", "111224", "111422", "121124", "121421", "141122", "141221", "112214",
    "112412", "122114", "122411", "142112", "142211", "241211", "221114", "413111", "241112", "134111",
    "111242", "121142", "121241", "114212", "124112", "124211", "411212", "421112", "421211", "212141",
    "214121", "412121", "111143", "111341", "131141", "114113", "114311", "411113", "411311", "113141",
    "114131", "311141", "411131", "211412", "211214", "211232", "2331112",
]


def generate_code128_svg_markup(value, module_width=2, height=88):
    raw_value = str(value or "").strip()
    if not raw_value:
        return ""
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in raw_value):
        return ""

    code_values = [104] + [ord(ch) - 32 for ch in raw_value]
    checksum_total = 104
    for index, code in enumerate(code_values[1:], start=1):
        checksum_total += code * index
    code_values.append(checksum_total % 103)
    code_values.append(106)

    quiet_zone = 10 * module_width
    x = quiet_zone
    rects = []
    for code in code_values:
        pattern = CODE128_PATTERNS[code]
        for idx, width_char in enumerate(pattern):
            segment_width = int(width_char) * module_width
            if idx % 2 == 0:
                rects.append(f'<rect x="{x}" y="0" width="{segment_width}" height="{height}" fill="#0f172a" />')
            x += segment_width
    total_width = x + quiet_zone
    text_y = height + 18
    safe_label = (
        raw_value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="{height + 26}" '
        f'viewBox="0 0 {total_width} {height + 26}" preserveAspectRatio="xMidYMin meet" '
        f'role="img" aria-label="Barcode {safe_label}" style="display:block;margin:24px auto;background:#ffffff;">'
        f'<rect width="{total_width}" height="{height + 26}" fill="#ffffff" rx="8" ry="8" />'
        + "".join(rects) +
        f'<text x="{total_width / 2}" y="{text_y}" text-anchor="middle" font-family="Inter, Arial, sans-serif" '
        f'font-size="14" font-weight="700" fill="#0f172a">{safe_label}</text>'
        '</svg>'
    )


def generate_code128_svg_data_uri(value, module_width=2, height=88):
    svg = generate_code128_svg_markup(value, module_width=module_width, height=height)
    if not svg:
        return ""
    return f"data:image/svg+xml;charset=utf-8,{quote(svg)}"
