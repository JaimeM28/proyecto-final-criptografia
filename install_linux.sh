#!/bin/bash
--@Autor: Jaime Manuel Miranda Serrano
--@Fecha creación: 03/12/2025
--@Descripción: Script de instalacion de wallet CLI en distribuciones linux basadas en ubuntu/debian
set -e

echo "Verificando Python 3..."
if ! command -v python3 &>/dev/null; then
    echo "Python no está instalado. Instalando..."
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip
    echo "Python instalado. Reinicia la terminal y ejecuta este script de nuevo."
    read -p "Presiona Enter para salir..."
    exit 1
fi

echo "Creando entorno virtual..."
python3 -m venv venv

echo "Activando entorno virtual..."
# activa el entorno virtual para que pip y python usen el venv
source venv/bin/activate

echo "Instalando wallet CLI..."
pip install .
echo "Instalación completada"

echo
echo "Activa el entorno virtual para usar la CLI"
echo
echo "    bash/zsh: source venv/bin/activate"
echo "    fish:     source venv/bin/activate.fish"
echo
