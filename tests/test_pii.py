from promptguard.pii import redact


def test_redacts_email():
    r = redact("Contact me at tony@example.com please.")
    assert "[EMAIL_1]" in r.text
    assert "tony@example.com" not in r.text
    assert r.restore() == "Contact me at tony@example.com please."


def test_redacts_phone():
    r = redact("Call 469-833-2503 anytime.")
    assert "[PHONE_1]" in r.text


def test_redacts_valid_ssn():
    r = redact("SSN: 078-05-1120")
    assert "[SSN_1]" in r.text


def test_rejects_implausible_ssn():
    # area 666 is never issued
    r = redact("SSN: 666-05-1120")
    assert "[SSN_1]" not in r.text
    assert "666-05-1120" in r.text


def test_redacts_valid_card_luhn():
    # well-known Luhn-valid test card number
    r = redact("Card: 4532015112830366")
    assert "[CARD_1]" in r.text


def test_rejects_invalid_card_luhn():
    # random 16 digits, fails Luhn
    r = redact("Order number: 1234567890123456")
    assert "[CARD_1]" not in r.text


def test_redacts_address():
    r = redact("I live at 123 Main St, come by.")
    assert "[ADDRESS_1]" in r.text


def test_multiple_items_numbered_independently():
    r = redact("Email a@x.com or b@y.com")
    assert "[EMAIL_1]" in r.text
    assert "[EMAIL_2]" in r.text


def test_no_pii_passthrough():
    r = redact("Nothing sensitive here.")
    assert r.text == "Nothing sensitive here."
    assert r.mapping == {}
