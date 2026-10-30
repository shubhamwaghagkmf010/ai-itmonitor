"""Spreadsheet-safe values for CSV exports.

A cell that starts with = + - @ (or a tab / carriage return) is run as a formula by Excel and
LibreOffice. Hostnames, employee names and device names come from the network and from people who
are not administrators, so exports prefix such cells with an apostrophe, which makes them plain text."""

_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value):
    if isinstance(value, str) and value.startswith(_TRIGGERS):
        return "'" + value
    return value


def csv_safe_row(values):
    return [csv_safe(v) for v in values]
