from try_tools.core.logging import mask


def test_mask_password_assignment():
    assert "hunter2" not in mask("password=hunter2")
    assert "masqué" in mask("password=hunter2")


def test_mask_token_colon():
    assert "abc123" not in mask('api_key: "abc123"')


def test_mask_authorization_header():
    out = mask("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
    assert "payload" not in out
    assert "Bearer" in out


def test_mask_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc-def_123"
    assert jwt not in mask(f"token found {jwt} in body")


def test_mask_preserves_field_name():
    out = mask("secret=topsecret")
    assert out.startswith("secret=")
    assert "topsecret" not in out


def test_mask_plain_text_untouched():
    assert mask("port 80 open on host") == "port 80 open on host"
