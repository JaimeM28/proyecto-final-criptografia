
from pathlib import Path
from getpass import getpass
import argparse

from .keystore import create, DEFAULT_KEYSTORE_PATH
from .address import load_address_from_keystore

def _read_passphrase(prompt: str = "Passphrase: ") -> str:
    pw = getpass(prompt)
    if not pw:
        raise SystemExit("Passphrase vacía; operación cancelada.")
    return pw

def cmd_wallet_init(args: argparse.Namespace) -> None:
    path = Path(args.path) if args.path else DEFAULT_KEYSTORE_PATH
    if path.exists() and not args.force:
        raise SystemExit(f"Ya existe {path}. Usa --force para sobrescribir (¡cuidado!).")
    passphrase = _read_passphrase("Nueva passphrase: ")
    confirm = _read_passphrase("Confirma passphrase: ")
    if passphrase != confirm:
        raise SystemExit("Las passphrases no coinciden.")
    doc = create(passphrase, path)
    print(f"Keystore creado en: {path}")
    print(f"Esquema: {doc['scheme']}")
    print(f"Public key (b64): {doc['pubkey_b64']}")

def cmd_wallet_address(args: argparse.Namespace) -> None:
    path = Path(args.path) if args.path else DEFAULT_KEYSTORE_PATH
    if not path.exists():
        raise SystemExit(f"No se encontró el keystore en: {path}")

    scheme, pubkey_b64, address = load_address_from_keystore(path)

    print(f"Keystore: {path}")
    print(f"Esquema: {scheme}")
    print(f"Dirección: {address}")
    print(f"Public key (b64): {pubkey_b64}")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wallet", description="cold wallet CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # wallet init
    sp = sub.add_parser("init", help="Crear un keystore nuevo")
    sp.add_argument("--path", help="Ruta del keystore (default: app/keystore.json)")
    sp.add_argument("--force", action="store_true", help="Sobrescribir si existe")
    sp.set_defaults(func=cmd_wallet_init)
    #wallet address
    sp = sub.add_parser("address", help="Mostrar la dirección derivada del keystore")
    sp.add_argument("--path", help="Ruta del keystore (default: app/keystore.json)")
    sp.set_defaults(func=cmd_wallet_address)
    
    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()