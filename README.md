# Proyecto Final - Cold Wallet 

**Objetivo:** Implementación de un wallet en frío con generación de llaves, almacenamiento seguro, firma y verificación de transacciones.

**Implementación:**
Este proyecto implementa un **cold crypto wallet** completamente fuera de red, con los componentes principales que se utilizan en los wallets reales:
- Generación de llaves Ed25519  
- Almacenamiento seguro mediante Argon2id + AES-256-GCM  
- Firma criptográfica de transacciones  
- Verificación completa con control de *replay*  
- Simulación de red mediante `inbox/`, `outbox/` y `verified/`




# 1. Instalación y ejecución

## 1.1 Clonar repositorio

```bash
git clone https://github.com/JaimeM28/proyecto-final-criptografia
cd proyecto-final-criptografia
```

---

Se integraron **instaladores automáticos** para Linux, macOS y Windows (escoger el que te sea útil segun tu S.O.).

# 1.2 Instalación en Linux

Ejecuta:

```bash
./install_linux.sh
```

Si el sistema marca falta de permisos:

```bash
chmod +x install_linux.sh
./install_linux.sh
```

### Activar entorno virtual

```bash
source venv/bin/activate
```

Desactivar:

```bash
deactivate
```

---

# 1.2.1 Instalación en macOS

Ejecuta:

```bash
./install_macos.sh
```

Si aparece error de permisos:

```bash
chmod +x install_macos.sh
./install_macos.sh
```

### Activar entorno virtual

```bash
source venv/bin/activate
```

Desactivar:

```bash
deactivate
```

---

# 1.2.2 Instalación en Windows

Ejecuta:

```powershell
install_windows.bat
```

Este script crea:

- el entorno virtual `venv\`
- instala dependencias
- habilita el comando `wallet` a través de `wallet.cmd`

### Activar entorno virtual en Windows

PowerShell:

```powershell
.\env\Scripts\Activate.ps1
```

CMD:

```cmd
venv\Scripts\activate.bat
```

Desactivar:

```powershell
deactivate
```

---

# 1.5 Uso del wallet (CLI)

### Crear un keystore

```bash
wallet init
```

### Mostrar la dirección pública

```bash
wallet address
```

### Firmar una transacción

```bash
wallet sign --to <direccion> --value <valor> --nonce <n>
```

Ejemplo:

```bash
wallet sign --to 0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB --value 10 --nonce 1
```

→ Guarda `outbox/tx_1.json`

### Procesar transacciones recibidas

```bash
wallet recv
```

- Verifica firma Ed25519  
- Deriva dirección desde pubkey  
- Verifica nonce (protección contra replay)  
- Mueve transacciones válidas a `verified/`

---

# 1.6 Ejecución de pruebas unitarias

```bash
pytest -v
```

Incluye:

- pruebas del keystore  
- firma y canonicalización  
- verificación criptográfica  
- protección de nonce  
- pruebas negativas (bad signature, wrong address, altered field)  
- golden vectors reproducibles  

---

# 2. Versiones de librerías (requirements.txt)

El proyecto utiliza las siguientes dependencias exactas:

| Librería | Versión | Uso |
|---------|---------|-----|
| **argon2-cffi** | **25.1.0** | KDF Argon2id para derivar claves |
| **argon2-cffi-bindings** | **25.1.0** | Bindings nativos necesarios por Argon2 |
| **cffi** | **2.0.0** | Interoperabilidad con librerías C |
| **cryptography** | **46.0.3** | AES-256-GCM (AEAD) para cifrado del keystore |
| **pycparser** | **2.23** | Dependencia interna para CFFI |
| **PyNaCl** | **1.6.1** | Firmas Ed25519 (SigningKey / VerifyKey) |
| **pytest** | **>=9.0.1** | Ejecución de pruebas unitarias |
| **pycryptodome** | **>=3.20.0** | Implementación de Keccak-256 para derivación de direcciones |

### Instalar dependencias manualmente

```bash
pip install -r requirements.txt
```

---

# 3. Threat Model Summary

### ✔ Amenazas consideradas

- Robo o manipulación del keystore  
- Alteración del contenido de transacciones  
- Suplantación del remitente  
- Replay attacks  
- Corrupción del keystore  

### ✘ Amenazas fuera de alcance

- Malware / keyloggers / rootkits  
- Compromiso del sistema operativo  
- Ataques físicos o side-channel  
- Ataques criptográficos avanzados  
- Conectividad a blockchain real  

---

# 4. Limitaciones conocidas

- No soporta **BIP-39** (semillas mnemónicas)  
- No implementa **HD wallets (BIP-32/BIP-44)**  
- Solo existe **una dirección**  
- No hay soporte **multisig**  
- No usa **TPM**, Secure Enclave o HSM  
- Flujo offline simulado con carpetas locales  
- Validaciones de transacción son básicas  

---
