# AIGatekeeper Integrations

Esta carpeta contiene configuraciones para integrar AIGatekeeper con populares asistentes de IA.

## Estructura

```
integrations/
├── README.md                 # Este archivo
├── install-integrations.ps1  # Script de instalación (Windows)
├── install-integrations.sh  # Script de instalación (Linux/Mac)
├── vscode/                   # VSCode integration
│   ├── README.md
│   ├── settings.json
│   └── tasks.json
├── cursor/                   # Cursor IDE integration
│   ├── README.md
│   └── mcp.json
├── nova/                     # Nova AI integration
│   └── README.md
├── alice/                    # Alice AI integration  
│   └── README.md
└── build/                    # Build AI integration
    └── README.md
```

## Instalación Rápida

### Windows (PowerShell)

```powershell
# Instalar todas las integraciones
.\integrations\install-integrations.ps1 -All

# Instalar solo VSCode y Cursor
.\integrations\install-integrations.ps1 -Integrations vscode,cursor

# Desinstalar
.\integrations\install-integrations.ps1 -Uninstall
```

### Linux/Mac (Bash)

```bash
# Hacer ejecutable
chmod +x integrations/install-integrations.sh

# Instalar todas
./integrations/install-integrations.sh --all

# Instalar específicas
./integrations/install-integrations.sh --vscode --nova
```

## Uso Directo (sin integración)

Si prefieres usar AIGatekeeper directamente desde la terminal:

```bash
# Activar entorno virtual
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\Activate.ps1  # Windows

# Sanitizar código (remover metadatos de IA)
python -m src.cli sanitize scan tu_archivo.py

# Escaneo de seguridad
python -m src.cli shield scan tu_archivo.py

# Podar contexto (reducir código enviado a IA)
python -m src.cli prune extract tu_archivo.py --task "optimizar función X"

# Ejecutar agente con todas las protecciones
python -m src.cli run execute "tu prompt aquí" --block
```

## Configuración por Editor

### VSCode

1. Copia `vscode/tasks.json` a `.vscode/tasks.json`
2. Copia `vscode/settings.json` a `.vscode/settings.json`
3. Presiona `Ctrl+Shift+P` → "Tasks: Run Task" → selecciona una tarea ZTC

**Tareas disponibles:**
- `ZTC: Security Scan` - Escanea el archivo actual
- `ZTC: Prune Context` - Poda contexto para tarea específica
- `ZTC: Sanitize Code` - Limpia metadatos

### Cursor IDE

1. Agrega configuración MCP en `.cursor/mcp.json`
2. Cursor usará ZTC-Wrapper automáticamente

### Nova, Alice, Build

Consulta los README.md en cada carpeta para instrucciones específicas.

## Variables de Entorno

```bash
# Habilitar ZTC-Wrapper
export ZTC_ENABLED=true

# Bloquear en problemas críticos
export ZTC_BLOCK_CRITICAL=true

# Sanitizar input/output
export ZTC_SANITIZE_INPUT=true
export ZTC_SANITIZE_OUTPUT=true

# Podar contexto automáticamente
export ZTC_PRUNE_CONTEXT=true

# Ruta de Python
export ZTC_PYTHON=python
```

## Verificar Instalación

```bash
python -m src.cli demo
python -m src.cli run check
```

## Solución de Problemas

### "Python not found"
- Verifica que el entorno virtual esté instalado: `ls venv/`
- Actívalo: `source venv/bin/activate` o `.\venv\Scripts\Activate.ps1`

### "Module not found: src"
- Asegúrate de estar en la raíz del proyecto ZTC-Wrapper
- Verifica PYTHONPATH

### Integración no funciona
- Consulta el README.md específico del editor
- Ejecuta el comando directamente para verificar que ZTC funciona:
  ```bash
  python -m src.cli shield scan tu_archivo.py
  ```

## Agregar Nueva Integración

Para agregar soporte para otro editor/AI:

1. Crea una nueva carpeta en `integrations/`
2. Agrega README.md con instrucciones específicas
3. Agrega archivos de configuración relevantes
4. Actualiza este README con el nuevo editor

---
**AIGatekeeper** - Seguridad Zero-Trust para Agentes de IA