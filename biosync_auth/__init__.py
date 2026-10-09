"""Autenticador BioSync: importe a janela pelo pacote ou execute com -m."""

__all__ = ["MenuAutenticacao"]


def __getattr__(name):
    if name == "MenuAutenticacao":
        from .app import MenuAutenticacao
        return MenuAutenticacao
    raise AttributeError(name)
