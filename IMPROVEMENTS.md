# 🛡️ AIGatekeeper - Mejoras y Roadmap

Ideas y funcionalidades para mejorar el proyecto. ¡Anímate a contribuir!

---

## 🚀 Mejoras Prioritarias (Alta Prioridad)

### 1. Integración con Tree-Sitter
- **Descripción**: Implementar análisis AST real usando tree-sitter en lugar de regex
- **Estado**: Pendiente
- **Dificultad**: Alta
- **Beneficio**: Precisión 10x mayor en detección de funciones y dependencias

```python
# Instalación de lenguajes
pip install tree-sitter-python tree-sitter-javascript tree-sitter-typescript
```

### 2. Wrapper para Agentes de IA
- **Descripción**: CLI que envuelve llamadas a agentes IA con sanitización automática
- **Estado**: ✅ Completado en v2.1.0
- **Dificultad**: Media
- **Comando**: `ag wrap "prompt" --agent claude`

### 3. Dashboard Web (UI)
- **Descripción**: Interfaz visual para ver estadísticas de seguridad, tokens ahorrados, etc.
- **Estado**: Pendiente
- **Dificultad**: Media
- **Tecnologías sugeridas**: Streamlit o Flask + HTMX

---

## 🔧 Mejoras Técnicas (Media Prioridad)

### 4. Soporte para más lenguajes backend (v3.0.0)
- **Descripción**: Agregar patrones de detección para Ruby, Kotlin, C#, Swift, Scala y otros lenguajes backend
- **Estado**: 📅 Planificado para v3.0.0
- **Archivos a modificar**: `src/detector/zombie_detector.py`, `core/src/scanner.cpp`
- **Dificultad**: Media

### 5. Análisis de Dependencias Peligrosas
- **Descripción**: Detectar paquetes npm/pip vulnerables o maliciosos
- **Estado**: Pendiente
- **Dificultad**: Media
- **Beneficio**: Prevenir supply chain attacks

```python
# Integrar con:
# - PyAudit API (Python)
# - npm audit (JavaScript)
```

### 6. Configuración Personalizable
- **Descripción**: Archivo de configuración `ag.yaml` para personalizar reglas
- **Estado**: ✅ Completado en v2.1.0
- **Dificultad**: Baja
- **Comando**: `ag config init` crea `ag.yaml` en el proyecto

---

## 🎯 Mejoras de Funcionalidad (Baja Prioridad)

### 7. Git Hooks Mejorados
- **Descripción**: 
  - Hook pre-push para revisar todo el directorio
  - Hook post-commit con stats de tokens ahorrados
- **Estado**: Pendiente
- **Dificultad**: Baja

### 8. Exportar Reportes
- **Descripción**: Generar reportes HTML/JSON de hallazgos de seguridad
- **Estado**: Pendiente
- **Dificultad**: Baja

```bash
run.bat shield scan ./src --report=security-report.html
```

### 9. Modo "Strict" (Bloqueo Total)
- **Descripción**: Opción para bloquear commits que contengan cualquier alerta de seguridad
- **Estado**: Pendiente
- **Dificultad**: Baja

### 10. Integración con IDEs
- **Descripción**: 
  - VS Code Extension
  - Plugin para JetBrains
- **Estado**: Pendiente
- **Dificultad**: Alta

---

## 📊 Métricas a Implementar

### 11. Dashboard de Métricas
- Tokens ahorrados por sesión
- Cantidad de vulnerabilidades detectadas
- Archivos sanitizados
- Reducción promedio de contexto

---

## 🧪 Ideas Experimentales

### 12. AI-Powered Context Inference
- **Descripción**: Usar un modelo pequeño (local) para inferir qué funciones son relevantes basándose en la tarea
- **Estado**: Idea
- **Dificultad**: Muy Alta
- **Nota**: Requiere ollama o similar instalado localmente

### 13. Plugin System
- **Descripción**: Sistema de plugins para que usuarios creen sus propios detectores
- **Estado**: Idea
- **Dificultad**: Alta

---

## 🤝 Cómo Contribuir

1. Fork del repositorio
2. Crear branch: `git checkout -b feature/nueva-caracteristica`
3. Implementar mejora
4. Agregar tests
5. Commit y push
6. Crear Pull Request

---

## 📋 Checklist de Implementación

### ✅ Completado
- [x] **Wrapper CLI** (`ag wrap`) — v2.1.0
- [x] **Archivo de configuración** (`ag.yaml`) — v2.1.0
- [x] **File Watcher** (`ag watch`) — v2.1.0

### 📅 Pendiente
- [ ] **Soporte más lenguajes backend** (Ruby, Kotlin, C#, Swift, Scala) — v3.0.0
- [ ] **Engine de ML** para detección avanzada — v3.1.0
- [ ] Tree-Sitter integration
- [ ] Dashboard web
- [ ] Análisis de dependencias
- [ ] Reportes HTML
- [ ] Modo strict
- [ ] VS Code Extension

---

*¿Tenés una idea? ¡Abrí un issue o mandá un PR! 🛡️*
