"""Crée (ou révoque) le jeton d'accès d'un analyste déclaré dans config/analysts.yaml.

    python -m scripts.create_token jdupont
    python -m scripts.create_token jdupont --revoke
"""

from __future__ import annotations

import argparse
import sys

from app.auth import TokenStore
from config.settings import load_settings
from gateway.policy import IdentityDirectory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Jetons d'accès des analystes")
    parser.add_argument("analyst_id")
    parser.add_argument("--revoke", action="store_true")
    args = parser.parse_args(argv)
    settings = load_settings()
    settings.ensure_dirs()
    identity = IdentityDirectory.load(settings.analysts_path).get(args.analyst_id)
    store = TokenStore(settings.data_dir / "tokens.json")
    if args.revoke:
        print(f"{store.revoke(args.analyst_id)} jeton(s) révoqué(s) pour {args.analyst_id}")
        return 0
    token = store.issue(args.analyst_id)
    print(f"Jeton pour {identity.analyst_id} ({identity.role}) — à conserver, il ne sera plus affiché :")
    print(token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
