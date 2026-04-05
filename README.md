# 🛡️ Zero-Trust AI Context Wrapper (ZTC-Wrapper)

**"No confíes en la IA, verifica el contexto, limpia el rastro."**

[Español](./README.md) | [English](./README_EN.md)

---

## ¿Qué es ZTC-Wrapper?

ZTC-Wrapper es un **middleware de seguridad y optimización** para desarrolladores que utilizan agentes de IA (como Claude Code, OpenCode, GPT, etc.) y desean:

- 🛡️ **Privacidad:** Evitar que secretos, API Keys o rutas locales viajen a la nube
- 💰 **Economía:** Reducir hasta 70% el consumo de tokens usando poda AST
- 🔒 **Seguridad:** Detectar y bloquear patrones de código obsoletos y vulnerables

---

## ⚡ Instalación

```bash
# Clonar el repositorio
git clone https://github.com/Leoshi123/zero-trust-ai-agent.git
cd zero-trust-ai-agent

# Instalar dependencias
pip install -r requirements.txt

# Uso básico
python -m src.cli --help
```

---

## 📦 Módulos

### 1. Sanitizador de Metadatos (Ghost-Cleaner) 🔧
Limpia el código generado por la IA:
- Rutas absolutas → relativas
- Comentarios de pensamiento interno
- IDs de sesión y tokens

### 2. Extractor AST (Context-Pruner)
Reduce el contexto enviado a la IA usando análisis sintáctico.

### 3. Detector Zombi (Legacy-Shield)
Identifica funciones obsoletas y propone alternativas seguras.

---

## 🛡️ Filosofía de Seguridad

> **"Zero Trust"**: No confíes en nadie, verifica todo.

Este proyecto opera bajo el principio de **Privacidad por Diseño**. Ningún dato sale de tu máquina sin pasar por los filtros de seguridad.

---

## 📄 Licencia

MIT License - Copyright (c) 2026 Leoshi
