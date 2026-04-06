# 🛡️ Zero-Trust AI Agent Wrapper (Agente de Confianza Cero)

[![Tests](https://github.com/Leoshi123/-Zero-Trust-AI-Agent-Wrapper-o-Agente-de-Confianza-Cero-/actions/workflows/ci.yml/badge.svg)](https://github.com/Leoshi123/-Zero-Trust-AI-Agent-Wrapper-o-Agente-de-Confianza-Cero-/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/Leoshi123/-Zero-Trust-AI-Agent-Wrapper-o-Agente-de-Confianza-Cero-/branch/main/graph/badge.svg)](https://codecov.io/gh/Leoshi123/-Zero-Trust-AI-Agent-Wrapper-o-Agente-de-Confianza-Cero-)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20macOS%20%7C%20Linux-blue.svg)](https://github.com/Leoshi123/-Zero-Trust-AI-Agent-Wrapper-o-Agente-de-Confianza-Cero-)

> 🌐 Available in: English, Español

**"No confíes en la IA, verifica el contexto, limpia el rastro."**

Un middleware de seguridad y optimización para desarrolladores que utilizan agentes de IA (Claude Code, OpenCode, GPT, etc.) y desean evitar el envío de datos sensibles, reducir el gasto de tokens y eliminar código vulnerable.

---

## 🛡️ Características

- 🧹 **Limpiador de Metadatos**: Elimina comentarios, rutas absolutas y firmas de modelos de IA del código generado
- 🚫 **Detector de Secretos**: Bloquea API keys, tokens y credenciales antes de que se escriban en disco
- ⚠️ **Filtro de Código Peligroso**: Detecta +60 funciones vulnerables en múltiples lenguajes
- 🪝 **Git Hooks Integrados**: Se ejecuta automáticamente en cada commit
- 🤖 **AI Agent Wrapper**: Envuelve llamadas a Claude Code/OpenCode con sanitización automática
- 🌐 **Multi-plataforma**: Windows, macOS, Linux (todas las distribuciones)
- 🌎 **Multi-idioma (i18n)**: Español + English (más idiomas en desarrollo)

---

## 🌐 Lenguajes Soportados

| Lenguaje | Patrones | Estado |
|----------|---------|--------|
| 🐍 **Python** | 24 | ✅ |
| 💻 **JavaScript/Node.js** | 20+ | ✅ |
| 📘 **TypeScript** | 15+ | ✅ |
| 🔥 **Go** | 6 | ✅ |
| 🦀 **Rust** | 5 | ✅ |
| ☕ **Java** | 4 | ✅ |
| 🔧 **C/C++** | 4 | ✅ |
| 🐘 **PHP** | 15+ | ✅ |
| ⚛️ **React 19** | 10+ | ✅ |

### Tipos de vulnerabilidades detectadas

- **Code Execution**: `eval()`, `exec()`, `system()`, `shell_exec()`
- **SQL Injection**: Concatenación en queries sin prepared statements
- **XSS**: `innerHTML`, `dangerouslySetInnerHTML`, `document.write()`
- **Command Injection**: `subprocess`, `child_process`, `exec()` con concatenación
- **Deserialization**: `unserialize()`, `pickle.loads()`, `ObjectInputStream`
- **Path Traversal**: `file_get_contents` con input de usuario
- **Hardcoded Secrets**: API keys, passwords, tokens
- **Deprecated Libraries**: `mysql_query`, `eval`, `gets()`
- **Type Safety**: `@ts-ignore`, `any`, unsafe casts

---

## 🚀 Instalación

### Requisitos

- Python 3.11+
- Windows / macOS / Linux

### Pasos

```bash
# Clonar el repositorio
git clone https://github.com/Leoshi123/-Zero-Trust-AI-Agent-Wrapper-o-Agente-de-Confianza-Cero-.git
cd zero-trust-ai-agent

# Instalar dependencias
pip install -r requirements.txt

# Instalar Git Hooks (opcional)
python -m src.cli hooks install

# Verificar instalación
python -m src.cli --help
```

### Uso del CLI

```bash
# Sanitizar código (limpiar metadata)
python -m src.cli sanitize input.py

# Escanear vulnerabilidades
python -m src.cli scan input.py --language python

# Podar contexto para la IA
python -m src.cli prune input.py --task "fix function login"
```

---

## 🌐 Web Dashboard

Ejecuta el dashboard web para una interfaz visual:

```bash
python server.py
```

Luego abre: **http://localhost:4901**

### Features del Dashboard

- 📊 Stats en tiempo real
- 🔍 Scanner de código interactivo
- 🧹 Sanitizador de metadata
- 📜 Historial de actividad
- 🌙 UI dark estilo Engram

---

## 🌍 i18n (Internacionalización)

El proyecto soporta múltiples idiomas:

| Código | Idioma | Estado |
|--------|--------|--------|
| `es` | Español | ✅ Default |
| `en` | English | ✅ |

### Cambiar idioma

```python
# En tu código
from src.config import ZTCConfig

config = ZTCConfig.load()
config.language = "en"  # English
config.save()
```

---

## 🔧 Configuración

Crea un archivo `.ztcrc` en la raíz de tu proyecto:

```json
{
  "language": "es",
  "languages_to_scan": ["python", "javascript", "php"],
  "block_critical": true,
  "max_context_lines": 500,
  "exclude_patterns": ["tests/*", "node_modules/*"]
}
```

---

## 🤝 Contribuir

1. Fork el repositorio
2. Crear branch: `git checkout -b feature/nueva-caracteristica`
3. Implementar mejora
4. Agregar tests
5. Commit y push
6. Crear Pull Request

---

## 📋 Roadmap

| Versión | Feature |
|---------|---------|
| v1.0.0 | Initial release |
| v1.0.1 | Multi-language (Go, Rust, Java, C/C++) |
| v1.0.2 | Tests para nuevos lenguajes |
| v1.0.3 | Web Dashboard |
| v1.1.0 | **JS, PHP, React 19, TypeScript** (actual) |
| v1.2.0 | Scripts de instalación multi-plataforma |
| v1.3.0 | i18n completo |
| v1.4.0 | Dashboard 3D |
| v1.5.0 | MCP Server nativo |

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

- [MoureDev](https://moure.dev) - Por la inspiración de aprendizaje continuo
- [Gentleman Programming](https://gentlemanprogramming.com) - Por la filosofía de calidad
- [Comunidad](https://discord.com/invite/gentleman-programming-769863833996754944) - Por el apoyo

---

**🛡️ Hecho con ❤️ para la comunidad**
