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
- **Descripción**: Crear un CLI que envuelva llamadas a Claude Code/OpenCode y aplique sanitización automática
- **Estado**: Pendiente
- **Dificultad**: Media
- **Beneficio**: Uso seamless - todo pasa por los filtros automáticamente

```bash
# Uso propuesto
ag run "claude code" --sanitize --prune
```

### 3. Dashboard Web (UI)
- **Descripción**: Interfaz visual para ver estadísticas de seguridad, tokens ahorrados, etc.
- **Estado**: Pendiente
- **Dificultad**: Media
- **Tecnologías sugeridas**: Streamlit o Flask + HTMX

---

## 🔧 Mejoras Técnicas (Media Prioridad)

### 4. Soporte para más lenguajes
- **Descripción**: Agregar patrones de detección para Go, Rust, Java, C++
- **Estado**: Pendiente
- **Archivos a modificar**: `src/detector/zombie_detector.py`

```python
# Ejemplo para Go
ZombiePattern(
    pattern=r'exec\.Command\s*\(',
    severity=Severity.CRITICAL,
    description="Command injection risk",
    alternative="Use flag package for user input",
    language="go"
)
```

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
- **Estado**: Pendiente
- **Dificultad**: Baja
- **Beneficio**: Adaptar a diferentes proyectos/equipos

```yaml
# ag.yaml ejemplo
sanitizer:
  remove_comments: true
  remove_paths: true
  
detector:
  blocked_functions:
    - eval
    - exec
    - shell=True
    
prune:
  max_context_lines: 500
```

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

- [ ] Tree-Sitter integration
- [ ] Wrapper CLI
- [ ] Dashboard web
- [ ] Soporte Go/Rust/Java
- [ ] Análisis de dependencias
- [ ] Archivo de configuración
- [ ] Reportes HTML
- [ ] Modo strict
- [ ] VS Code Extension

---

*¿Tenés una idea? ¡Abrí un issue o mandá un PR! 🛡️*
