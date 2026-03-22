from web.app import THEME_DEFAULTS, _sanitize_theme


def test_sanitize_theme_rejects_invalid_hex_values():
    theme = _sanitize_theme(
        {
            "mode": "dark",
            "dark": {
                "bg_primary": "not-a-color",
                "text_primary": "#ffffff",
            },
        }
    )
    assert theme["dark"]["bg_primary"] == THEME_DEFAULTS["dark"]["bg_primary"]


def test_sanitize_theme_normalizes_invalid_mode_to_system():
    theme = _sanitize_theme({"mode": "banana"})
    assert theme["mode"] == "system"
