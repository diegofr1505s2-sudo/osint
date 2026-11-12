"""Validation locale et interprétation prudente des identifiants IBAN/VIN."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IBANResult:
    value: str
    country: str
    length: int
    expected_length: int | None
    length_valid: bool
    checksum_valid: bool
    bank_code: str | None = None
    bank_name: str | None = None

    @property
    def structurally_valid(self) -> bool:
        return self.length_valid and self.checksum_valid


def normalize_iban(value: str) -> str:
    return "".join(value.split()).upper()


def validate_iban(value: str, lengths: dict[str, int], bank_names: dict[str, str] | None = None) -> IBANResult:
    iban = normalize_iban(value)
    country = iban[:2]
    expected = lengths.get(country)
    length_valid = bool(expected and len(iban) == expected)
    checksum_valid = False
    if len(iban) >= 5 and iban[:2].isalpha() and iban[2:4].isdigit() and iban[4:].isalnum():
        try:
            checksum_valid = int("".join(str(int(char, 36)) for char in iban[4:] + iban[:4])) % 97 == 1
        except ValueError:
            checksum_valid = False
    bank_code = iban[4:9] if country in ("FR", "MC") and len(iban) == 27 else None
    return IBANResult(iban, country, len(iban), expected, length_valid, checksum_valid, bank_code, (bank_names or {}).get(bank_code or ""))


@dataclass(frozen=True)
class VINResult:
    value: str
    valid_format: bool
    region: str | None
    manufacturer: str | None
    model_year: str | None
    serial_number: str | None
    check_digit_valid: bool | None


def normalize_vin(value: str) -> str:
    return "".join(value.split()).replace("-", "").upper()


def _vin_check_digit(vin: str) -> bool | None:
    # Le contrôle est obligatoire principalement pour les VIN nord-américains.
    if vin[0] not in "123456789ABCDEFGHJKLMNPRSTVWXYZ":
        return None
    transliteration = {**{str(i): i for i in range(10)}, "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
                       "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9, "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9}
    weights = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)
    total = sum(transliteration[c] * weights[i] for i, c in enumerate(vin))
    expected = "X" if total % 11 == 10 else str(total % 11)
    return vin[8] == expected


def decode_vin(value: str, regions: dict[str, str], manufacturers: dict[str, str]) -> VINResult:
    vin = normalize_vin(value)
    valid = len(vin) == 17 and all(char in "ABCDEFGHJKLMNPRSTVWXYZ0123456789" for char in vin)
    if not valid:
        return VINResult(vin, False, None, None, None, None, None)
    year_codes = "ABCDEFGHJKLMNPRSTVWXY123456789"
    code = vin[9]
    if code in year_codes:
        year = 2010 + year_codes.index(code)
        model_year = str(year) if year <= 2027 else f"{year} ou {year - 30}"
    else:
        model_year = None
    return VINResult(vin, True, regions.get(vin[0]), manufacturers.get(vin[:3]), model_year, vin[11:], _vin_check_digit(vin))
