@echo off
echo Verificando Python 3...
python --version >nul 2>&1 || (
    echo Python no esta instalado. Instalando con winget...
    winget install --id Python.Python.3.12 --silent --override "--install-options=InstallAllUsers=1 PrependPath=1"
    echo Python instalado. Reinicia la terminal y ejecuta este script de nuevo.
    pause
    exit /b
)

echo Creando entorno virtual...
python -m venv venv

echo Activando entorno virtual...
call venv\Scripts\activate.bat

echo Instalando wallet CLI...
pip install .
echo Instalacion completada

echo Activa el entorno virtual para usar la CLI 
echo.
echo    cmd: venv\Scripts\activate.bat
echo    power shell: .\venv\Scripts\Activate.ps1
echo.



