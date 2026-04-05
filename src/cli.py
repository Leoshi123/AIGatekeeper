"""
🛡️ ZTC-Wrapper - CLI Principal

Interfaz de línea de comandos para:
- Sanitizador de metadatos
- Extractor AST
- Detector de código zombi
- Git hooks
"""

import click
import sys
import os
from pathlib import Path

from src.sanitizer import MetadataSanitizer
from src.ast_parser import ASTExtractor
from src.detector import LegacyShield, Severity
from src.wrapper import AIAgentWrapper, WrapperConfig


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """🛡️ ZTC-Wrapper - Security & Context Optimization for AI Agents"""
    pass


# ============================================================
# COMANDOS DEL SANITIZADOR
# ============================================================


@cli.group()
def sanitize():
    """Comandos de sanitización de metadatos"""
    pass


@sanitize.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Archivo de salida")
def scan(file_path: str, output: str):
    """Escanea y limpia un archivo de código."""

    with open(file_path, "r", encoding="utf-8") as f:
        original_code = f.read()

    sanitizer = MetadataSanitizer()
    result = sanitizer.sanitize(original_code)

    click.echo(f"✅ Archivo procesado: {file_path}")
    click.echo(f"📊 Elementos removidos: {len(result.removed_items)}")

    if result.removed_items:
        click.echo("\n🔍 Detalles:")
        for tipo, contenido in result.removed_items:
            truncated = contenido[:60] + "..." if len(contenido) > 60 else contenido
            click.echo(f"  • [{tipo}]: {truncated}")

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(result.cleaned_code)
        click.echo(f"\n💾 Guardado en: {output}")
    else:
        click.echo("\n📄 Código limpio:")
        click.echo("-" * 40)
        click.echo(result.cleaned_code)


@sanitize.command()
@click.argument("code", required=False)
def clean(code: str):
    """Limpia código desde argumento o stdin."""

    if not code:
        code = click.get_text_stream("stdin").read()

    sanitizer = MetadataSanitizer()
    result = sanitizer.sanitize(code)

    click.echo(result.cleaned_code)

    if result.removed_items:
        click.echo(f"\n⚠️  Elementos removidos: {len(result.removed_items)}", err=True)


# ============================================================
# COMANDOS DEL EXTRACTOR AST
# ============================================================


@cli.group()
def prune():
    """Comandos de poda de contexto AST"""
    pass


@prune.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option(
    "--task", "-t", default="general optimization", help="Descripción de la tarea"
)
@click.option(
    "--functions", "-f", multiple=True, help="Funciones específicas a incluir"
)
@click.option("--output", "-o", type=click.Path(), help="Archivo de salida")
def extract(file_path: str, task: str, functions: tuple, output: str):
    """Extrae contexto mínimo relevante para la tarea."""

    extractor = ASTExtractor()
    func_list = list(functions) if functions else None

    pruned = extractor.prune(file_path, task, func_list)
    stats = extractor.get_stats(pruned)

    click.echo(f"📊 Análisis de: {file_path}")
    click.echo(f"\n📉 Reducción: {stats['reduction_percent']}%")
    click.echo(f"   • Original: {stats['original_lines']} líneas")
    click.echo(f"   • Podado:   {stats['pruned_lines']} líneas")

    click.echo(f"\n📦 Imports ({len(pruned.imports)}):")
    for imp in pruned.imports[:5]:
        click.echo(f"  {imp}")
    if len(pruned.imports) > 5:
        click.echo(f"  ... y {len(pruned.imports) - 5} más")

    click.echo(f"\n🔧 Funciones Relevantes ({len(pruned.relevant_functions)}):")
    for func in pruned.relevant_functions:
        deps = ", ".join(func.dependencies) if func.dependencies else "ninguna"
        click.echo(f"  • {func.name}")
        click.echo(f"    Dependencias: {deps}")

    if pruned.signatures:
        click.echo(f"\n📝 Firmas Omitidas ({len(pruned.signatures)}):")
        for sig in pruned.signatures[:3]:
            click.echo(f"  {sig}")
        if len(pruned.signatures) > 3:
            click.echo(f"  ... y {len(pruned.signatures) - 3} más")

    if output:
        output_code = _build_pruned_output(pruned)
        with open(output, "w", encoding="utf-8") as f:
            f.write(output_code)
        click.echo(f"\n💾 Guardado en: {output}")


@prune.command()
@click.argument("file_path", type=click.Path(exists=True))
def stats(file_path: str):
    """Muestra estadísticas de reducción potencial."""

    extractor = ASTExtractor()
    pruned = extractor.prune(file_path, "analyze")
    stats = extractor.get_stats(pruned)

    click.echo(f"📈 Estadísticas para: {file_path}")
    click.echo(f"\n  Líneas originales:  {stats['original_lines']}")
    click.echo(f"  Líneas podadas:     {stats['pruned_lines']}")
    click.echo(f"  Reducción:          {stats['reduction_percent']}%")
    click.echo(f"  Funciones válidas:  {stats['functions_kept']}")
    click.echo(f"  Funciones omitidas: {stats['functions_omitted']}")


def _build_pruned_output(pruned) -> str:
    """Construye el código podado."""
    lines = []
    lines.append("# ===== IMPORTS =====")
    lines.extend(pruned.imports)
    lines.append("")
    lines.append("# ===== SIGNATURES (OMITTED BODY) =====")
    lines.extend(pruned.signatures)
    lines.append("")
    lines.append("# ===== RELEVANT FUNCTIONS =====")
    for func in pruned.relevant_functions:
        lines.append(f"# --- {func.name} ---")
        lines.append(func.signature)
        lines.append(func.body)
        lines.append("")
    return "\n".join(lines)


# ============================================================
# COMANDOS DEL DETECTOR ZOMBI
# ============================================================


@cli.group()
def shield():
    """Comandos del detector de código zombi"""
    pass


@shield.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option(
    "--block/--no-block", default=False, help="Bloquear si hay problemas críticos"
)
def scan(file_path: str, block: bool):
    """Escanea un archivo en busca de código vulnerable."""

    detector = LegacyShield()
    results = detector.scan_file(file_path)

    if not results:
        click.echo(f"✅ {file_path}: Sin problemas detectados")
        return

    summary = detector.get_summary(results)

    click.echo(f"\n🔍 Escaneo de: {file_path}")
    click.echo(f"📊 Total problemas: {summary['total']}")
    click.echo(f"   🛑 Críticos: {summary['critical']}")
    click.echo(f"   ⚠️  Altos:    {summary['high']}")
    click.echo(f"   📝 Medios:   {summary['medium']}")
    click.echo(f"   💡 Bajos:    {summary['low']}")

    # Mostrar detalles
    for r in results:
        color = _get_severity_color(r.pattern.severity)
        click.echo(f"\n{color}📍 Línea {r.line_number}:{r.pattern.severity.value}")
        click.echo(f"   {r.line_content[:80]}")
        click.echo(f"   💡 {r.pattern.description}")
        click.echo(f"   ✅ {r.pattern.alternative}")

    # Decision
    if block and detector.block_critical(results):
        click.echo("\n🛑 BLOQUEADO: Problemas críticos detectados")
        sys.exit(1)


@shield.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option("--extensions", "-e", multiple=True, help="Extensiones a escanear")
def scan_dir(directory: str, extensions: tuple):
    """Escanea todos los archivos en un directorio."""

    exts = list(extensions) if extensions else [".py", ".js", ".ts", ".jsx", ".tsx"]

    from src.detector import scan_directory as scan_dir_fn

    results = scan_dir_fn(directory, exts)

    if not results:
        click.echo(f"✅ Directorio limpio: sin problemas detectados")
        return

    # Agregar resultados de todos los archivos
    all_results = []
    for file_path, file_results in results.items():
        all_results.extend(file_results)

    summary = LegacyShield().get_summary(all_results)

    click.echo(f"\n🔍 Escaneo de directorio: {directory}")
    click.echo(f"📊 Archivos con problemas: {len(results)}")
    click.echo(f"📊 Total problemas: {summary['total']}")
    click.echo(f"   🛑 Críticos: {summary['critical']}")
    click.echo(f"   ⚠️  Altos:    {summary['high']}")
    click.echo(f"   📝 Medios:   {summary['medium']}")

    # Listar archivos con problemas
    for file_path, file_results in results.items():
        click.echo(f"\n📄 {file_path}")
        for r in file_results[:3]:  # Max 3 por archivo
            click.echo(
                f"   {r.pattern.severity.value}: {r.pattern.description[:50]}..."
            )


def _get_severity_color(severity: Severity) -> str:
    """Retorna el color según la severidad."""
    colors = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "⚪",
    }
    return colors.get(severity, "⚪")


# ============================================================
# COMANDOS DE GIT HOOKS
# ============================================================


@cli.group()
def hooks():
    """Comandos de integración con Git hooks"""
    pass


@hooks.command()
def install():
    """Instala los git hooks de seguridad."""

    git_dir = ".git"
    hooks_dir = os.path.join(git_dir, "hooks")

    # Verificar que es un repo git
    if not os.path.exists(git_dir):
        click.echo("❌ No es un repositorio Git")
        sys.exit(1)

    # Crear directorio de hooks si no existe
    os.makedirs(hooks_dir, exist_ok=True)

    # Crear pre-commit hook
    hook_content = """#!/bin/sh
# ZTC-Wrapper Pre-commit Hook
# Este hook escanea el código antes de cada commit

echo "🔍 ZTC-Wrapper: Escaneando código..."

# Obtener archivos staged
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

# Directorios a excluir
EXCLUDE_DIRS=".git|node_modules|venv|__pycache__|build"

# Escaneo de código zombi
for file in $STAGED_FILES; do
    case "$file" in
        *.py|*.js|*.ts|*.jsx|*.tsx)
            # Ejecutar detector
            python -m src.cli shield scan "$file" --block || {
                echo "❌ El commit fue bloqueado por problemas de seguridad"
                exit 1
            }
            ;;
    esac
done

echo "✅ Escaneo completado"
exit 0
"""

    hook_path = os.path.join(hooks_dir, "pre-commit")

    with open(hook_path, "w", encoding="utf-8") as f:
        f.write(hook_content)

    # Hacer ejecutable (Linux/Mac)
    try:
        os.chmod(hook_path, 0o755)
    except Exception:
        pass

    click.echo(f"✅ Pre-commit hook instalado en: {hook_path}")
    click.echo("\n📋 El hook ejecutará:")
    click.echo("   • Detector de código zombi en cada commit")
    click.echo("   • Bloqueo automático si hay vulnerabilidades críticas")


@hooks.command()
def uninstall():
    """Desinstala los git hooks."""

    hook_path = ".git/hooks/pre-commit"

    if os.path.exists(hook_path):
        os.remove(hook_path)
        click.echo("✅ Pre-commit hook desinstalado")
    else:
        click.echo("⚠️  No hay hook instalado")


# ============================================================
# COMANDOS DEL WRAPPER (AI Agent)
# ============================================================


@cli.group()
def run():
    """Comandos del wrapper de agentes IA"""
    pass


@run.command()
@click.argument("prompt")
@click.option(
    "--agent", "-a", default="claude", help="Agente a usar (claude, opencode)"
)
@click.option(
    "--sanitize-input/--no-sanitize-input", default=True, help="Sanitizar input"
)
@click.option(
    "--sanitize-output/--no-sanitize-output", default=True, help="Sanitizar output"
)
@click.option("--prune/--no-prune", default=False, help="Podar contexto AST")
@click.option(
    "--block/--no-block", default=True, help="Bloquear si hay problemas críticos"
)
@click.option(
    "--context",
    "-c",
    type=click.Path(exists=True),
    help="Archivo de contexto para podar",
)
def execute(
    prompt: str,
    agent: str,
    sanitize_input: bool,
    sanitize_output: bool,
    prune: bool,
    block: bool,
    context: str,
):
    """Ejecuta un agente IA con sanitización."""

    wrapper = AIAgentWrapper()

    # Verificar si el agente está disponible
    if agent != "demo":
        available = wrapper.check_agent_available(agent)
        if not available:
            click.echo(f"⚠️  {agent} no está disponible. Usando modo demo.")
            agent = "demo"

    config = WrapperConfig(
        agent_command=agent,
        sanitize_input=sanitize_input,
        sanitize_output=sanitize_output,
        prune_context=prune,
        block_critical=block,
        context_file=context,
    )

    click.echo(f"🚀 Ejecutando {agent} con ZTC-Wrapper...\n")

    result = wrapper.run(prompt, config)

    # Mostrar resultados
    click.echo(f"📥 Input sanitizado: {'✅' if result.sanitized_input else '❌'}")
    click.echo(f"📤 Output sanitizado: {'✅' if result.sanitized_output else '❌'}")
    click.echo(f"✂️  Contexto podado: {'✅' if result.pruned_context else '❌'}")
    click.echo(f"🔒 Problemas de seguridad: {result.security_issues_found}")

    if result.blocked:
        click.echo(f"\n🛑 OUTPUT BLOQUEADO por seguridad")
        click.echo(result.stdout)
    else:
        click.echo(f"\n✅ Output:")
        click.echo(result.stdout)

    if result.stderr:
        click.echo(f"\n⚠️  Stderr:\n{result.stderr}")

    click.echo(f"\n📊 Return code: {result.returncode}")


@run.command()
def check():
    """Verifica qué agentes están disponibles."""

    wrapper = AIAgentWrapper()

    click.echo("=== 🛡️ Agentes Disponibles ===\n")

    agents = ["claude", "opencode"]

    for agent in agents:
        available = wrapper.check_agent_available(agent)
        status = "✅ Disponible" if available else "❌ No disponible"
        click.echo(f"  {agent}: {status}")


# ============================================================
# COMANDO DEMO
# ============================================================


@cli.command()
def demo():
    """Ejecuta una demostración completa."""

    click.echo("=== 🛡️ ZTC-Wrapper Demo ===\n")

    # Demo sanitizer
    click.echo("--- Sanitizador de Metadatos ---")
    sample_code = """// Generated by Claude Code
// Thinking: This function validates user input

def authenticate(path: str):
    # Reading from C:/Users/Leoshi/secrets/api_key.txt
    key = open('/home/user/.env').read()
    
    session_id = "sk-ant-api03-abc123"
    model_id = "gpt-4-turbo"
    return process(key)
"""

    sanitizer = MetadataSanitizer()
    result = sanitizer.sanitize(sample_code)

    click.echo("Elementos removidos:")
    for tipo, contenido in result.removed_items:
        click.echo(f"  [{tipo}]: {contenido[:50]}...")

    # Demo extractor
    click.echo("\n--- Extractor AST ---")

    sample_file = "/tmp/demo_ast.py"
    sample_code2 = """
import os
import json

def main():
    config = load_config()
    return process(config)

def load_config():
    return json.load(open("config.json"))

def process(data):
    return [transform(x) for x in data]

def transform(x):
    return x * 2

def helper():
    return "not needed"
"""

    with open(sample_file, "w") as f:
        f.write(sample_code2)

    extractor = ASTExtractor()
    pruned = extractor.prune(sample_file, "optimizar función process")
    stats = extractor.get_stats(pruned)

    click.echo(f"Reducción: {stats['reduction_percent']}%")
    click.echo(f"Funciones relevantes: {[f.name for f in pruned.relevant_functions]}")

    # Demo detector
    click.echo("\n--- Detector Zombi ---")

    sample_code3 = """
import os
import pickle

def unsafe():
    code = eval(user_input)
    return code

api_key = "sk-1234567890"
"""

    detector = LegacyShield()
    results = detector.scan_code(sample_code3)

    click.echo(f"Problemas encontrados: {len(results)}")
    for r in results:
        click.echo(f"  [{r.pattern.severity.value}] {r.pattern.description}")


if __name__ == "__main__":
    cli()
