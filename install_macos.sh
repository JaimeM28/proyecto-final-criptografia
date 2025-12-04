#!/bin/bash
--@Autor: Marco Antonio Machorro Villa
--@Fecha creación: 04/12/2025
--Script de instalación de wallet CLI en macOS

set -e

echo "Verificando Python 3..."
if ! command -v python3 &>/dev/null; then
    echo "Python 3 no está instalado."
    if command -v brew &>/dev/null; then
        echo "Instalando Python 3 con Homebrew..."
        brew update
        brew install python
        echo "Python instalado. Cierra y vuelve a abrir la terminal si es necesario."
    else
        echo "No se encontró Homebrew."
        echo "Instala Homebrew desde https://brew.sh y luego vuelve a ejecutar este script."
        read -p "Presiona Enter para salir..."
        exit 1
    fi
fi

echo "Creando entorno virtual..."
python3 -m venv venv

echo "Activando entorno virtual..."
# activamos el entorno virtual para que pip y python usen el venv
source venv/bin/activate

echo "Instalando wallet CLI..."
pip install .

echo "Instalación completada"

echo
echo "Activa el entorno virtual para usar la CLI:"
echo
echo "    zsh/bash: source venv/bin/activate"
echo