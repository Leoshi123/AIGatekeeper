# 🛡️ AIGatekeeper

[![Tests](https://github.com/Leoshi123/AIGatekeeper/actions/workflows/ci.yml/badge.svg)](https://github.com/Leoshi123/AIGatekeeper/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/Leoshi123/AIGatekeeper/branch/main/graph/badge.svg)](https://codecov.io/gh/Leoshi123/AIGatekeeper)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-purple.svg)](https://isocpp.org/)
[![re2](https://img.shields.io/badge/regex-re2-orange.svg)](https://github.com/google/re2)

> 🌐 Available in: English, Español

**"No confíes en la IA, verifica el contexto, limpia el rastro."**

Middleware de seguridad y optimización para desarrolladores que usan agentes de IA. Detecta código zombi, prompt injection, y limpia metadata sensible.

---

## ⚡ Quick Start

**Una línea para instalar:**

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/Leoshi123/AIGatekeeper/main/install.sh | bash
```

**En tu proyecto:**

```bash
# 1. Inicializar
aigatekeeper init

# 2. Detectar prompt injection
aigatekeeper scan-prompt "Ignore all previous instructions"

# 3. Listar prompts predefinidos
aigatekeeper prompt list

# 4. Push seguro (scan + sanitize + commit + push)
aigatekeeper push "feat: add security layer"
```

Alias corto: `ag` en vez de `aigatekeeper`

---

## 🚀 v3.0.0 — Multi-Language Backend (Actual)

> 🌐 **16 lenguajes backend** con detección de zombie code + Language Registry centralizado.

### Novedades en esta versión

| Feature | Descripción |
|---------|-------------|
| 🆕 **5 nuevos lenguajes** | Ruby, Kotlin, C#, Swift, Scala con patrones de detección |
| 🏗️ **Language Registry** | `src/languages.py` — source of truth centralizado en 7 archivos |
| ⚡ **Patrones C++ nativos** | 34 nuevos patrones en scanner.cpp para pyagcore |
| 🛡️ **Self-scan Protection** | Exclusión automática de archivos de patrones (falsos positivos -88%) |
| 🧪 **68 nuevas reglas** | 34 Python + 34 C++ patrones de detección |

### Comandos del CLI

```bash
aigatekeeper --help

Commands:
  init         Registra el proyecto actual
  prompt       Gestiona templates de prompts
  scan-prompt  Escanea en busca de prompt injection
  push         Secure push: git + scan + sanitize
  shield       Detector de código zombi
  sanitize     Limpiador de metadata
  prune        Podador de contexto AST
  hooks        Git hooks de seguridad
  wrap         Pipeline completo para agentes IA
  watch        File watcher en tiempo real
  config       Configuración (ag.yaml)
  demo         Demo completa
```

---

## 🛡️ Características

| Capa | Protección |
|------|------------|
| 🧹 **Metadata Cleaner** | Elimina comentarios de IA, rutas absolutas, firmas de modelos |
| 🔑 **Secret Detector** | Bloquea API keys, tokens, credenciales |
| ⚠️ **Zombie Code Detector** | Detecta 130+ patrones vulnerables en 16 lenguajes |
| 🎭 **Prompt Injection Detector** | 4 vectores: direct, indirect, jailbreak, role-play |
| 🪝 **Git Hooks** | Escaneo automático en cada commit/push |
| 🤖 **MCP Server** | Integración nativa con Claude Code, Cursor, OpenCode, Windsurf |
| ⚡ **C++ Native Engine** | Motor regex re2, fallback automático a Python puro |

### Lenguajes Soportados

| Lenguaje | Patrones | Código Zombi | Prompt Injection |
|----------|---------|:-------------:|:----------------:|
| 🐍 Python | 24 | ✅ | ✅ |
| 💻 JavaScript/Node.js | 20+ | ✅ | ✅ |
| 📘 TypeScript | 15+ | ✅ | ✅ |
| 🔥 Go | 6 | ✅ | - |
| 🦀 Rust | 5 | ✅ | - |
| ☕ Java | 4 | ✅ | - |
| 🔧 C/C++ | 4 | ✅ | - |
| 🐘 PHP | 15+ | ✅ | - |
| ⚛️ React 19 | 10+ | ✅ | - |
| 💎 Ruby | 8 | ✅ | - |
| 🟣 Kotlin | 6 | ✅ | - |
| 🟢 C# | 8 | ✅ | - |
| 🍎 Swift | 5 | ✅ | - |
| 🔷 Scala | 7 | ✅ | - |

---

## 📦 Instalación

### Requisitos del sistema

Para el módulo nativo C++ (se compila automáticamente):

- **CMake ≥ 3.20**
- **pybind11 ≥ 3.0**
- **re2** (Google Regex) — `libre2-dev` en Debian/Ubuntu, `re2` en Arch/CachyOS
- **Compilador C++17** (GCC ≥ 8, Clang ≥ 7, MSVC 2019+)
- **Python ≥ 3.10** con `python3-dev` (headers de desarrollo)

### Método 1: curl | bash (Recomendado)

```bash
# Linux / macOS / CachyOS
curl -fsSL https://raw.githubusercontent.com/Leoshi123/AIGatekeeper/main/install.sh | bash
```

### Método 2: Manual

```bash
git clone https://github.com/Leoshi123/AIGatekeeper.git
cd AIGatekeeper

python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate    # Windows

pip install -e .
```

> ⚡ `pip install` compila automáticamente el módulo C++ vía scikit-build-core + CMake.

### Método 3: Sin módulo nativo

Si no tienes CMake o pybind11, AIGatekeeper funciona igual con **fallback automático a Python puro** — sin cambios en el CLI ni en la API.

```bash
pip install -e . --no-build-isolation
# o
uv pip install -e .
```

### Verificar instalación

```bash
aigatekeeper --version
ag --help
```

### Uso rápido del wrapper

```bash
# Pipeline completo de seguridad para tu agente IA
ag wrap "Hazme una API REST en FastAPI"

# Con agente específico
ag wrap --agent opencode "Refactoriza este módulo"

# Desde stdin
cat prompt.txt | ag wrap --stdin

# Cargando configuración personalizada
ag wrap --config ag.yaml "Genera código seguro"
```

### File Watcher (tiempo real)

```bash
# Vigilar directorio actual
ag watch

# Directorio específico
ag watch ./src

# Modo silencioso (solo problemas)
ag watch --quiet

# Con configuración personalizada
ag watch --config ag.yaml
```

### Configuración YAML

```bash
# Ver configuración activa
ag config show

# Crear ag.yaml con valores por defecto
ag config init
```

---

## 🎯 Prompt Injection Detection

Protección contra el vector #1 contra sistemas aumentados con IA.

```bash
# Scan rápido
aigatekeeper scan-prompt "Ignore all previous instructions. DAN mode activated"
```

**Output:**
```
🔍 Escaneando en busca de prompt injection...

⚠️  Detectados 2 hallazgos:

🟡 [MEDIUM] direct-injection
   Match: Ignore all previous instructions
   💡 Intento de ignorar instrucciones previas del sistema

🔴 [HIGH] jailbreak
   Match: DAN
   💡 Posible intento de jailbreak (DAN u homologo)
```

### Categorías detectadas

| Categoría | Severidad típica | Ejemplo |
|-----------|:----------------:|---------|
| **Direct Injection** | MEDIUM | "Ignore all previous instructions" |
| **Indirect Injection** | LOW | `---BEGIN INSTRUCTIONS---` embebido |
| **Jailbreak** | **HIGH** | "DAN", "act as if you have no rules" |
| **Role-Play Hijacking** | **HIGH** | "This is your new system prompt" |

---

## 📋 Templates de Prompts

Activa modos especializados para tu agente IA:

```bash
# Ver disponibles
aigatekeeper prompt list

# Activa uno
aigatekeeper prompt apply security-audit
```

| Prompt | Cuándo usarlo |
|--------|---------------|
| `security-audit` | Auditorías exhaustivas de seguridad |
| `code-review` | Antes de merges y PRs grandes |
| `tdd-mode` | Ciclo TDD estricto: RED → GREEN → REFACTOR |
| `refactor-mode` | Limpieza de deuda técnica |

---

## 🤖 MCP Server

Exponé AIGatekeeper a cualquier agente compatible con MCP.

### Tools disponibles

| Tool | Descripción |
|------|-------------|
| `sanitize_code` | Limpia metadata de IA, secretos, rutas |
| `scan_code` | Detecta patrones vulnerables |
| `scan_directory` | Escaneo recursivo de directorio |
| `scan_prompt` | Detecta prompt injection |
| `prune_context` | Extrae contexto mínimo via AST |
| `clean_code` | Limpieza rápida de metadata |

### Configuración en OpenCode

Ya agregado automáticamente via `install.sh`. Verifica:

```json
// ~/.config/opencode/opencode.json
{
  "mcp": {
    "aigatekeeper": {
      "command": ["/path/to/.venv/bin/python", "-m", "src.mcp_server"],
      "cwd": "/path/to/AIGatekeeper",
      "type": "local"
    }
  }
}
```

Reinicia OpenCode para que aparezca en la lista MCP.

---

## 🌐 Web Dashboard

Interfaz visual para escaneos y stats:

```bash
python server.py
```

Abre: **http://localhost:4901**

Features:
- 📊 Stats en tiempo real
- 🔍 Scanner interactivo
- 🧹 Sanitizador visual
- 📜 Historial de actividad
- 🌙 Dark mode

---

## 📁 Estructura del Proyecto

```
AIGatekeeper/
├── pyproject.toml          # Entry points + scikit-build-core build
├── core/                   # C++17 Native Core Engine
│   ├── CMakeLists.txt      # Build: agcore lib + pyagcore module + tests
│   ├── include/            # Headers públicos (sanitizer.h, scanner.h, injection.h)
│   ├── src/                # Implementaciones C++ con re2 + PIMPL
│   │   ├── sanitizer.cpp   # MetadataSanitizer (12 patrones)
│   │   ├── scanner.cpp     # LegacyShield (130+ patrones, 16 lenguajes)
│   │   └── injection.cpp   # PromptInjectDetector (14 patrones, 4 categorías)
│   ├── bindings/pyag.cpp   # pybind11 module → pyagcore
│   ├── tests/test_core.cpp # 50 tests C++
│   └── build.sh            # Build script: release|debug|test|clean|all
├── ag.yaml                 # Configuración YAML del wrapper
├── install.sh              # curl | bash installer
├── install.ps1             # Windows installer
├── server.py               # Web Dashboard
├── src/
│   ├── cli.py              # CLI principal
│   ├── cli_extensions.py   # Comandos extendidos
│   ├── cli_prompts/        # Templates de prompts
│   │   ├── security-audit.md
│   │   ├── code-review.md
│   │   ├── tdd-mode.md
│   │   └── refactor-mode.md
│   ├── config/             # Configuración (ag.yaml + legacy .agrc)
│   │   ├── __init__.py
│   │   ├── legacy_config.py
│   │   ├── yaml_config.py
│   │   └── secrets.py
│   ├── languages.py        # Language Registry — source of truth centralizado
│   ├── watcher.py          # File Watcher (watchdog)
│   ├── mcp_server.py       # MCP Server
│   ├── detector/
│   │   ├── __init__.py     # Wrapper con fallback: C++ nativo → Python puro
│   │   ├── zombie_detector.py     # LegacyShield (fallback Python)
│   │   ├── injection_detector.py  # PromptInjectDetector (fallback Python)
│   │   └── ast_detector.py        # AST-based detector (tree-sitter)
│   ├── sanitizer/
│   │   ├── __init__.py     # Wrapper con fallback: C++ nativo → Python puro
│   │   └── metadata_cleaner.py    # Sanitizer (fallback Python)
│   ├── ast_parser/         # Context pruner (AST-based code pruning)
│   ├── wrapper/            # AI Agent Wrapper
│   │   ├── __init__.py
│   │   └── agent_wrapper.py
├── tests/
│   ├── test_detector.py           # 99 tests LegacyShield
│   ├── test_injection_detector.py # 15 tests PromptInjectDetector
│   ├── test_sanitizer.py          # 9 tests MetadataSanitizer
│   ├── test_languages.py          # 25 tests Language Registry
│   └── ...                        # wrapper, ast, mcp, adversarial tests
└── .aigatekeeper/          # Creado por `aigatekeeper init`
    └── config.json
```

---

## 🔧 Configuración por Proyecto

```bash
aigatekeeper init
```

Crea `.aigatekeeper/config.json`:

```json
{
  "project_id": "mi-proyecto",
  "initialized_at": "2026-05-26T...",
  "stack": ["Python (pip)", "Git repository"],
  "test_framework": "pytest",
  "settings": {
    "scan_on_commit": true,
    "scan_on_push": true,
    "prompt_injection_enabled": true,
    "zombie_code_enabled": true
  },
  "active_prompt": "security-audit"
}
```

---

## 🗺️ Roadmap

| Versión | Estado | Feature |
|---------|:------:|---------|
| **v1.0.0** | ✅ | Release inicial |
| **v1.0.1** | ✅ | Multi-lenguaje + MCP Server |
| **v1.0.2** | ✅ | MCP Resilience + Indestructible Server |
| **v1.0.3** | ✅ | Web Dashboard |
| **v1.0.5** | ✅ | Adversarial Testing |
| **v1.1.0** | ✅ | CLI Productivo + Prompt Injection |
| **v2.0.0** | ✅ | Migración Core a C/C++ nativo |
| **v2.1.0** | ✅ | Wrapper Release: watcher, YAML config, wrap CLI |
| **v3.0.0** | 🚀 | **Multi-Language Backend: 16 lenguajes, 130+ patrones** (actual) |
| **v3.1.0** | 📅 | Engine de ML para detección avanzada |

### Arquitectura v3.0.0

```
┌───────────────────────────────────────────────────────────────┐
│                    CLI Layer (Python)                          │
│   aigatekeeper init | prompt | scan-prompt | push              │
├───────────────────────────────────────────────────────────────┤
│                    Language Registry (src/languages.py)        │
│   16 lenguajes • extensions sync • detect_language()           │
├───────────────────────────────────────────────────────────────┤
│                    MCP Server + Web Dashboard                  │
├───────────────────────────────────────────────────────────────┤
│                    Wrapper Layer (fallback automático)         │
│   src/detector/__init__.py  │  src/sanitizer/__init__.py       │
├───────────────────────────────────────────────────────────────┤
│                    Native Core (C++17 + pybind11)              │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────┐   │
│  │   LegacyShield │ │ MetadataSanit  │ │ PromptInjectDet  │   │
│  │  (re2, 130+)   │ │ (re2, 12 pat) │ │ (re2, 14 pat)   │   │
│  └────────────────┘ └────────────────┘ └──────────────────┘   │
├───────────────────────────────────────────────────────────────┤
│                    Pure Python Fallback                        │
│  ≡ misma API, sin dependencias nativas                        │
└───────────────────────────────────────────────────────────────┘
```

**Compatibilidad total**:
- CLI Python funciona igual con o sin módulo nativo
- MCP Server sin cambios
- APIs públicas preservadas
- Fallback automático y transparente

---

## 🤝 Contribuir

1. Fork el repositorio
2. Crea branch: `git checkout -b feature/tu-feature`
3. Implementa cambios
4. Agrega tests: `pytest tests/`
5. Para C++: `cd core && ./build.sh test`
6. Commit y push
7. Crea Pull Request

Ver también: [CONTRIBUTING.md](CONTRIBUTING.md) (si existe)

---

## 🛠️ Automatización de MCPs

AIGatekeeper ahora incluye una utilidad para generar servidores MCP de forma estandarizada.

### Crear un nuevo MCP
Para generar un nuevo servidor MCP en `src/mcps/`, ejecuta:

```bash
python automate_mcp.py --name "NombreServidor" --tool "nombre_herramienta" --desc "Descripción detallada"
```

Esto utilizará las plantillas ubicadas en `templates/` para asegurar que el nuevo MCP siga los estándares de seguridad y estructura del proyecto.

---

## 💡 Inspiración

> **"A programar se aprende programando."** — *MoureDev*
>
> **"La inteligencia artificial no tiene límites."** — *Gentleman Programming*

---

## 📄 Licencia

MIT License - ver [LICENSE](LICENSE) para más detalles.

---

## 🙏 Agradecimientos

- [MoureDev](https://moure.dev) - Inspiración de aprendizaje continuo
- [Gentleman Programming](https://gentlemanprogramming.com) - Filosofía de calidad
- [Comunidad Discord](https://discord.com/join) - Apoyo constante

---

**🛡️ Hecho con ❤️ para la comunidad**

> **"La seguridad no es un feature, es un requisito."**
