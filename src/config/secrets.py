"""
🛡️ ZTC-Wrapper - Gestión de Secretos
"""
import os
from pathlib import Path
from dotenv import load_dotenv

def load_secrets():
    """
    Carga las variables de entorno desde el archivo .env
    """
    # Buscar el .env en la raíz del proyecto
    env_path = Path('.env').absolute()
    load_dotenv(dotenv_path=env_path)

def get_secret(key: str, default: str = None) -> str:
    """
    Obtiene un secreto del entorno.
    """
    return os.getenv(key, default)

# Carga automática al importar el módulo
load_secrets()
