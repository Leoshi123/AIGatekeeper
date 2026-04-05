# 🛡️ Zero-Trust AI Agent Wrapper (Agente de Confianza Cero)

**"No confíes en la IA, verifica el contexto, limpia el rastro."**

Un middleware de seguridad y optimización para desarrolladores que utilizan agentes de IA (Claude Code, OpenCode, GPT, etc.) y desean evitar el envío de datos sensibles, reducir el gasto de tokens y eliminar código vulnerable.

---

## 🛡️ Características

- 🧹 **Limpiador de Metadatos**: Elimina comentarios, rutas absolutas y firmas de modelos de IA del código generado
- 🚫 **Detector de Secretos**: Bloquea API keys, tokens y credenciales antes de que se escriban en disco
- ⚠️ **Filtro de Código Peligroso**: Prohíbe funciones vulnerables como `eval()`, `shell=True`, `innerHTML`, etc.
- 🪝 **Git Hooks Integrados**: Se ejecuta automáticamente en cada commit
- 🤖 **AI Agent Wrapper**: Envuelve llamadas a Claude Code/OpenCode con sanitización automática

---

## 💡 Inspiración y Filosofía

Este proyecto no nace de la nada, ni se conforma con las respuestas pre-entrenadas de modelos de 2019. Se construye bajo los pilares de quienes nos enseñaron que el código es un arte vivo:

> **"A programar se aprende programando."** — *MoureDev*
>
> **"La inteligencia artificial no tiene límites."** — *Gentleman Programming*

**ZTC-Wrapper** es mi respuesta a ese desafío. Es el puente entre el código que se aprende ensuciándose las manos y la potencia de una IA que no se detiene, pero que necesita un guardián para no comprometer nuestra seguridad ni nuestro presupuesto.

### ¿Por qué este proyecto hoy?

Si los modelos de IA fueron entrenados con datos del pasado (2019-2022), **ZTC-Wrapper** vive en el presente.

* **MoureDev** nos enseñó la importancia de las buenas prácticas y el aprendizaje continuo. Este wrapper evita que la IA te sugiera código "zombie" u obsoleto.
* **Gentleman Programming** nos mostró cómo orquestar la complejidad. Este sistema aplica arquitectura limpia para que el contexto sea quirúrgico y eficiente.

---

## 🚀 Instalación

```bash
git clone https://github.com/Leoshi123/-Zero-Trust-AI-Agent-Wrapper-o-Agente-de-Confianza-Cero-.git
cd zero-trust-ai-agent
pip install -r requirements.txt
python install_hooks.py
```

---

## 📋 Uso

```bash
# Windows (usar run.bat para evitar problemas de encoding)
run.bat --help

# Escanear un archivo
run.bat sanitize scan archivo.py

# Ver configuración
run.bat shield scan archivo.py

# Ejecutar agente IA con sanitización
run.bat run execute "Tu prompt aquí" --agent claude

# Verificar agentes disponibles
run.bat run check

# Modo interactivo
run.bat demo
```

---

## 🛡️ Funciones Prohibidas por Defecto

| Lenguaje | Funciones Bloqueadas |
|----------|---------------------|
| Python | `eval()`, `exec()`, `os.system()`, `subprocess` con `shell=True` |
| JavaScript | `eval()`, `document.write()`, `innerHTML` |
| Bash | `rm -rf` sin confirmación |

---

## 🎯 ¿Por qué este proyecto?

Los agentes de IA entrenados con código de 2019-2022 heredaron **deuda técnica de seguridad**. Este proyecto implementa el principio de **"Zero Trust"**: no confiar en ningún output de IA sin validar.

---

## 📄 Licencia

MIT License - Copyright (c) 2026 Leoshi
