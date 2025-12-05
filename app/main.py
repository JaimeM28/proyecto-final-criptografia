from pathlib import Path
from getpass import getpass
import argparse
import json
import base64

from .keystore import create, DEFAULT_KEYSTORE_PATH, load
from .address import load_address_from_keystore, address_from_pubkey
from .tx import Tx
from .signer import sign as sign_tx
from .verifier import verify_tx, commit_verification

OUTBOX_DIR = Path("outbox")


def _read_passphrase(prompt: str = "Passphrase: ") -> str:
    """
    En esta función se lee una passphrase desde la entrada estándar y valida que no esté vacía.

    Args:
        prompt (str): Mensaje a mostrar al usuario al solicitar la passphrase.

    Returns:
        str: Es la passphrase ingresada por el usuario.

    Raises:
        SystemExit: Si la passphrase ingresada está vacía.
    """
    pw = getpass(prompt)
    if not pw:
        raise SystemExit("Passphrase vacía; operación cancelada.")
    return pw


def cmd_wallet_init(args: argparse.Namespace) -> None:
    """
    Es el c omando CLI para inicializar un nuevo keystore en disco. Crea un archivo de keystore protegido con una passphrase, validando que no
    exista antes (al menos que se use un --force).

    Args:
        args (argparse.Namespace): Argumentos de línea de comandos que incluyen:
            path (str | None): Ruta del keystore a crear.
            force (bool): Indica si se debe sobrescribir un keystore existente.

    Returns:
        None ( ningun valor de retorno).

    Raises:
        SystemExit: Si el keystore ya existe y no se usa --force o si las passphrases ingresadas no coinciden.
    """
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
    """
    Es el comando CLI para mostrar la dirección derivada del keystore actual.

    Se pide la passphrase para descifrar el keystore, deriva la dirección a partir de la clave pública y la muestra junto con los metadatos básicos.

    Args:
        args (argparse.Namespace): Argumentos de línea de comandos donde se
            puede incluir:
            path (str | None): Ruta del keystore. Si no se especifica, se usa
                DEFAULT_KEYSTORE_PATH.

    Returns:
        None

    Raises:
        SystemExit: Si no se encuentra el keystore en la ruta indicada, o si la passphrase es incorrecta o la carga del keystore falla.
    """
    path = Path(args.path) if args.path else DEFAULT_KEYSTORE_PATH
    if not path.exists():
        raise SystemExit(f"No se encontró el keystore en: {path}")

    # Pedimos passphrase y validamos el keystore
    passphrase = _read_passphrase("Passphrase: ")
    try:
        
        state = load(passphrase, path)  # si la pass es incorrecta, aquí truena
    except Exception as e:
        raise SystemExit(f"Passphrase incorrecta o error al cargar el keystore")

    doc = state["doc"]
    pubkey_b64 = doc["pubkey_b64"]
    pubkey_bytes = base64.b64decode(pubkey_b64)
    address = address_from_pubkey(pubkey_bytes)

    print(f"Keystore: {path}")
    print(f"Esquema: {doc['scheme']}")
    print(f"Dirección: {address}")
    print(f"Public key (b64): {pubkey_b64}")


def cmd_wallet_sign(args: argparse.Namespace) -> None:
    """
    Es el comando CLI para crear y firmar una transacción, guardándola en "outbox/".
    Lo que hace es que carga la clave privada desde el keystore, construye una transacción con los parámetros indicados y la firma, en donde estará escribiendo el resultado en un archivo JSON.

    Args:
        args (argparse.Namespace): Argumentos de línea de comandos. Debe incluir:
            keystore (str | None): Ruta del keystore (opcional).
            to (str): Dirección de destino de la transacción.
            value (str | int | float): Valor a transferir.
            nonce (int): Nonce único de la transacción.
            gas_limit (int | None): Límite de gas (opcional).
            data_hex (str | None): Payload en hexadecimal (opcional).

    Returns:
        None

    Raises:
        SystemExit: Si no existe keystore en la ruta indicada o si la passphrase es incorrecta o no se puede cargar el keystore.
    """
    path = Path(args.keystore) if args.keystore else DEFAULT_KEYSTORE_PATH
    if not path.exists():
        raise SystemExit(f"No existe keystore en {path}. Ejecuta primero 'wallet init'.")

    passphrase = _read_passphrase("Passphrase: ")
    try:
        state = load(passphrase, path)
    except Exception as e:
        raise SystemExit(f"Passphrase incorrecta")
    sk = state["sk"]

    pubkey_bytes = state["pubkey_bytes"] # Usado para derivar la dirección
    from_addr = address_from_pubkey(pubkey_bytes)

    tx = Tx(
        from_addr=from_addr,
        to_addr=args.to,
        value=str(args.value),
        nonce=args.nonce,
        gas_limit=args.gas_limit,
        data_hex=args.data_hex,
    )
    tx_dict = tx.to_dict()

    signed_pkg = sign_tx(sk, tx_dict)

    OUTBOX_DIR.mkdir(exist_ok=True, parents=True)
    filename = f"tx_{tx_dict['nonce']}.json"
    out_path = OUTBOX_DIR / filename
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(signed_pkg, f, indent=2, ensure_ascii=False)

    print(f"Transacción firmada y guardada en {out_path}")
    
def cmd_wallet_recv(args: argparse.Namespace) -> None:
    """
    Es el comando CLI para procesar transacciones que entran desde el directorio "inbox/", lee los archivos JSON de la carpeta "inbox/", verifica cada transacción y
    si es válida actualiza el nonce tracker y mueve el archivo a "verified/".

    Args:
        args (argparse.Namespace): Argumentos de línea de comandos (no se usan actualmente, pero mejor se mantiene por consistencia con la interfaz CLI).

    Returns:
        None (no hay valor de retorno).
    """
    inbox_dir = Path("inbox")
    verified_dir = Path("verified")
    
    # Asegurar que existan los directorios
    if not inbox_dir.exists():
        print(f"No existe el directorio {inbox_dir}. Nada que recibir.")
        return
    verified_dir.mkdir(exist_ok=True)

    # Filtrar solo archivos JSON
    files = list(inbox_dir.glob("*.json"))
    
    if not files:
        print("Bandeja de entrada vacía.")
        return

    print(f"Procesando {len(files)} transacciones en '{inbox_dir}'...\n")

    for file_path in files:
        try:
            print(f"Verificando: {file_path.name} ... ", end="", flush=True)
            
            with file_path.open("r", encoding="utf-8") as f:
                signed_tx = json.load(f)

            is_valid, reason = verify_tx(signed_tx)

            if is_valid:
                # 1. Actualizar el Nonce Tracker
                commit_verification(signed_tx)
                
                # 2. Mover a carpeta verified
                destination = verified_dir / file_path.name
                file_path.rename(destination)
                print(f"VÁLIDA -> Movida a {destination}")
            else:
                print(f"INVÁLIDA ({reason})")

        except json.JSONDecodeError:
            print("ERROR (JSON corrupto)")
        except Exception as e:
            print(f"ERROR ({str(e)})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wallet", description="cold wallet CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # wallet init
    sp = sub.add_parser("init", help="Crear un keystore nuevo")
    sp.add_argument("--path", help="Ruta del keystore (default: app/keystore.json)")
    sp.add_argument("--force", action="store_true", help="Sobrescribir si existe")
    sp.set_defaults(func=cmd_wallet_init)

    # wallet address
    sp_addr = sub.add_parser("address", help="Mostrar la dirección derivada del keystore")
    sp_addr.add_argument("--path", help="Ruta del keystore (default: app/keystore.json)")
    sp_addr.set_defaults(func=cmd_wallet_address)

    # wallet sign
    sp_sign = sub.add_parser("sign", help="Crear y firmar una transacción")
    sp_sign.add_argument("--to", required=True, help="Destino de la transacción")
    sp_sign.add_argument("--value", required=True, help="Valor a transferir (string o número)")
    sp_sign.add_argument("--nonce", required=True, type=int, help="Nonce (uint64)")
    sp_sign.add_argument("--gas_limit", type=int, help="Gas limit (opcional)")
    sp_sign.add_argument("--data_hex", help="Payload en hex (opcional)")
    sp_sign.add_argument("--keystore", help="Ruta del keystore (opcional)")
    sp_sign.set_defaults(func=cmd_wallet_sign)
    
    # wallet recv
    sp_recv = sub.add_parser("recv", help="Procesar transacciones de inbox/")
    sp_recv.set_defaults(func=cmd_wallet_recv)

    return parser


def main(argv=None) -> None:
    """
    Esta funcion muy pequeña pero importante es el punto de entrada principal del programa CLI. Construye el parser de argumentos, interpreta los valores recibidos desde
    la línea de comandos (o desde la lista opcional "argv") y ejecuta la función que esta relacionada al subcomando seleccionado.

    Args:
        argv (list[str] | None): Lista opcional de argumentos que sustituye a los provenientes de la línea de comandos. Si es None, se usan
            automáticamente los argumentos del entorno del sistema.

    Returns:
        None (ningun valor de retorno).
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()