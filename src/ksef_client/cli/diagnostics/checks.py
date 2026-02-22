from __future__ import annotations

from typing import Any

from ..auth.keyring_store import get_token_store_mode, get_tokens
from ..config.loader import load_config


def run_preflight(profile: str | None = None) -> dict[str, Any]:
    config = load_config()
    selected_profile = None
    if profile is not None and profile.strip() != "":
        selected_profile = profile.strip()
    elif config.active_profile is not None and config.active_profile.strip() != "":
        selected_profile = config.active_profile.strip()

    selected_cfg = config.profiles.get(selected_profile) if selected_profile else None
    base_url = selected_cfg.base_url if selected_cfg else ""
    context_type = selected_cfg.context_type if selected_cfg else ""
    context_value = selected_cfg.context_value if selected_cfg else ""
    has_tokens = bool(get_tokens(selected_profile)) if selected_profile else False
    token_store_mode = get_token_store_mode()

    if selected_profile is None:
        profile_status = "WARN"
        profile_message = "No active profile is configured."
    elif selected_cfg is None:
        profile_status = "WARN"
        profile_message = f"Profile '{selected_profile}' is not configured."
    else:
        profile_status = "PASS"
        profile_message = "Profile found in config."

    checks = [
        {
            "name": "profile",
            "status": profile_status,
            "message": profile_message,
        },
        {
            "name": "base_url",
            "status": "PASS" if bool(base_url) else "WARN",
            "message": (
                base_url
                if bool(base_url)
                else (
                    "Missing base_url in profile."
                    if selected_profile is not None
                    else "Profile is not selected."
                )
            ),
        },
        {
            "name": "context",
            "status": "PASS" if bool(context_type and context_value) else "WARN",
            "message": (
                "Context configured."
                if bool(context_type and context_value)
                else (
                    "Missing context_type/context_value in profile."
                    if selected_profile is not None
                    else "Profile is not selected."
                )
            ),
        },
        {
            "name": "tokens",
            "status": "PASS" if has_tokens else "WARN",
            "message": (
                "Stored tokens available."
                if has_tokens
                else (
                    "No stored tokens for profile."
                    if selected_profile is not None
                    else "Profile is not selected."
                )
            ),
        },
        {
            "name": "token_store",
            "status": "PASS",
            "message": token_store_mode,
        },
    ]

    overall = "PASS" if all(item["status"] == "PASS" for item in checks) else "WARN"
    return {
        "status": overall,
        "profile": selected_profile,
        "checks": checks,
    }
