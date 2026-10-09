"""Entrada compatível: o código do autenticador fica em biosync_auth/app.py."""

from biosync_auth.app import CryptoEnvelope, MenuAutenticacao, collect_hwid, main

if __name__ == "__main__":
    raise SystemExit(main())
