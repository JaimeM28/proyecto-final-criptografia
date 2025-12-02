
from pathlib import Path
from getpass import getpass
import argparse
import json

from .keystore import create, DEFAULT_KEYSTORE_PATH, load
from .tx import Tx
from .signer import sign as sign_tx

OUTBOX_DIR = Path("outbox")

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

def cmd_wallet_sign(args: argparse.Namespace) -> None:
    # Ruta del keystore
    path = Path(args.keystore) if args.keystore else DEFAULT_KEYSTORE_PATH
    if not path.exists():
        raise SystemExit(f"No existe keystore en {path}. Ejecuta primero 'wallet init'.")

    # Passphrase y carga de llave
    passphrase = _read_passphrase("Passphrase: ")
    state = load(passphrase, path)
    sk = state["sk"]
    # de momento usamos la pubkey en base64 como 'from' (más adelante puedes cambiarlo a address)
    from_addr = state["doc"]["pubkey_b64"]

    # Construir la transacción
    tx = Tx(
        from_addr=from_addr,
        to_addr=args.to,
        value=str(args.value),
        nonce=args.nonce,
        gas_limit=args.gas_limit,
        data_hex=args.data_hex,
    )
    tx_dict = tx.to_dict()

    # Firmar
    signed_pkg = sign_tx(sk, tx_dict)

    # Guardar en outbox/
    OUTBOX_DIR.mkdir(exist_ok=True, parents=True)
    filename = f"tx_{tx_dict['nonce']}.json"
    out_path = OUTBOX_DIR / filename
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(signed_pkg, f, indent=2, ensure_ascii=False)

    print(f"Transacción firmada y guardada en {out_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wallet", description="cold wallet CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # wallet init
    sp = sub.add_parser("init", help="Crear un keystore nuevo")
    sp.add_argument("--path", help="Ruta del keystore (default: app/keystore.json)")
    sp.add_argument("--force", action="store_true", help="Sobrescribir si existe")
    sp.set_defaults(func=cmd_wallet_init)

    # wallet sign
    sp_sign = sub.add_parser("sign", help="Crear y firmar una transacción")
    sp_sign.add_argument("--to", required=True, help="Destino de la transacción")
    sp_sign.add_argument("--value", required=True, help="Valor a transferir (string o número)")
    sp_sign.add_argument("--nonce", required=True, type=int, help="Nonce (uint64)")
    sp_sign.add_argument("--gas_limit", type=int, help="Gas limit (opcional)")
    sp_sign.add_argument("--data_hex", help="Payload en hex (opcional)")
    sp_sign.add_argument("--keystore", help="Ruta del keystore (opcional)")
    sp_sign.set_defaults(func=cmd_wallet_sign)

     
    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()