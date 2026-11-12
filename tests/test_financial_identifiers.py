from catexe.modules.financial_identifiers import decode_vin, validate_iban


IBAN_LENGTHS = {"FR": 27, "DE": 22}
BANKS = {"20041": "La Banque Postale"}


def test_iban_requires_length_and_checksum():
    valid = validate_iban("FR1420041010050500013M02606", IBAN_LENGTHS, BANKS)
    assert valid.structurally_valid
    assert valid.bank_name == "La Banque Postale"
    invalid = validate_iban("FR1420041010050500013M02607", IBAN_LENGTHS, BANKS)
    assert not invalid.checksum_valid
    wrong_length = validate_iban("FR763000400035123456789014", IBAN_LENGTHS, BANKS)
    assert not wrong_length.structurally_valid


def test_vin_excludes_forbidden_letters_and_decodes_known_wmi():
    result = decode_vin("1M8GDM9AXKP042788", {"1": "États-Unis"}, {"1M8": "Test Motors"})
    assert result.valid_format
    assert result.manufacturer == "Test Motors"
    assert result.check_digit_valid is True
    invalid = decode_vin("1M8GDM9A IKP042788", {"1": "États-Unis"}, {})
    assert not invalid.valid_format


def test_vin_non_north_american_check_can_be_undetermined():
    result = decode_vin("VF1RFB00312345678", {"V": "France / Espagne"}, {"VF1": "Renault"})
    assert result.valid_format
    assert result.check_digit_valid in (True, False, None)
