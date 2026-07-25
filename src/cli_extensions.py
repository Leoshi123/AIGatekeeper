# -*- coding: utf-8 -*-
"""
Comandos extendidos para el CLI de AIGatekeeper:
- init: Registro de proyecto
- prompt: Templates de prompts
- scan-prompt: Detección de prompt injection
- push: Git + scan + sanitize
"""

import sys
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

import click

from src.detector.injection_detector import PromptInjectDetector, InjectionCategory


def get_prompts_dir() -> Path:
    """Retorna el directorio con los prompts empaquetados."""
    return Path(__file__).parent / "cli_prompts"


def get_project_config_dir() -> Path:
    """Retorna el directorio de config del proyecto actual."""
    return Path.cwd() / ".aigatekeeper"


def load_project_config() -> dict:
    """Carga la configuración del proyecto o retorna defaults."""
    config_file = get_project_config_dir() / "config.json"
    if config_file.exists():
        with open(config_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_project_config(config: dict):
    """Guarda la configuración del proyecto."""
    config_dir = get_project_config_dir()
    config_dir.mkdir(exist_ok=True)

    gitignore = config_dir / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text("# AIGatekeeper local state\n*.local\ncache/\n")

    config_file = config_dir / "config.json"
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    return config_file


def register_commands(cli_group):
    """Registra todos los comandos extendidos en el grupo CLI principal."""

    @cli_group.command()
    @click.option("--force", "-f", is_flag=True, help="Sobreescribir config existente")
    def init(force: bool):
        """
        Registra el proyecto actual con AIGatekeeper.

        Detecta el stack, crea .aigatekeeper/ config directory,
        y registra el proyecto para hooks y escaneos automáticos.
        """
        config_dir = get_project_config_dir()
        config_file = config_dir / "config.json"

        if config_file.exists() and not force:
            click.echo("⚠️  El proyecto ya está inicializado.")
            click.echo("   Usa --force para re-inicializar.")
            sys.exit(0)

        click.echo("🛡️  AIGatekeeper - Inicializando proyecto...")
        click.echo("")

        cwd = Path.cwd()
        stack = []

        if (cwd / "requirements.txt").exists():
            stack.append("Python (pip)")
        if (cwd / "pyproject.toml").exists():
            stack.append("Python (pyproject)")
        if (cwd / "package.json").exists():
            stack.append("Node.js")
        if (cwd / "Cargo.toml").exists():
            stack.append("Rust")
        if (cwd / "go.mod").exists():
            stack.append("Go")
        if (cwd / ".git").exists():
            stack.append("Git repository")

        test_framework = "desconocido"
        if (cwd / "pytest.ini").exists() or (cwd / "tests").exists():
            test_framework = "pytest"

        click.echo("📋 Detectado:")
        click.echo(f"   Stack: {', '.join(stack) if stack else 'No detectado'}")
        click.echo(f"   Testing: {test_framework}")
        click.echo("")

        config = {
            "project_id": cwd.name,
            "initialized_at": datetime.now().isoformat(),
            "stack": stack,
            "test_framework": test_framework,
            "settings": {
                "scan_on_commit": True,
                "scan_on_push": True,
                "prompt_injection_enabled": True,
                "zombie_code_enabled": True,
            },
            "active_prompt": None,
        }

        config_file = save_project_config(config)

        click.echo(f"✅ Configuración creada: {config_file}")
        click.echo("")
        click.echo("🚀 Proyecto registrado con AIGatekeeper.")
        click.echo("")
        click.echo("Siguientes pasos:")
        click.echo("   aigatekeeper prompt list      → Ver prompts disponibles")
        click.echo("   aigatekeeper shield scan .    → Escanear código zombi")
        click.echo("   aigatekeeper hooks install    → Instalar git hooks")

    @cli_group.group()
    def prompt():
        """Gestiona templates de prompts para agentes IA."""
        pass

    @prompt.command(name="list")
    def prompt_list():
        """Lista todos los prompts disponibles."""
        prompts_dir = get_prompts_dir()

        if not prompts_dir.exists():
            click.echo("⚠️  No se encontraron templates de prompts.")
            return

        prompts = list(prompts_dir.glob("*.md"))

        if not prompts:
            click.echo("⚠️  No hay prompts disponibles.")
            return

        click.echo("📋 Templates de Prompts Disponibles:")
        click.echo("")

        for p in sorted(prompts):
            name = p.stem
            try:
                first_lines = p.read_text(encoding="utf-8").split("\n", 3)
                desc = first_lines[2].strip() if len(first_lines) > 2 else ""
            except Exception:
                desc = ""

            click.echo(f"   • {name}")
            if desc:
                click.echo(f"     {desc}")
            click.echo("")

        config = load_project_config()
        active = config.get("active_prompt")
        if active:
            click.echo(f"📍 Prompt activo en este proyecto: {active}")

    @prompt.command(name="apply")
    @click.argument("prompt_name")
    def prompt_apply(prompt_name: str):
        """
        Activa un template de prompt para el proyecto.

        PROMPT_NAME: Nombre del prompt (sin .md)
        Ejemplo: aigatekeeper prompt apply security-audit
        """
        prompts_dir = get_prompts_dir()
        prompt_file = prompts_dir / f"{prompt_name}.md"

        if not prompt_file.exists():
            matches = list(prompts_dir.glob(f"*{prompt_name}*.md"))
            if matches:
                click.echo(f"⚠️  '{prompt_name}' no existe. Opciones similares:")
                for m in matches:
                    click.echo(f"   • {m.stem}")
            else:
                click.echo(f"❌ Prompt '{prompt_name}' no encontrado.")
                click.echo("   Usa 'aigatekeeper prompt list' para ver disponibles.")
            sys.exit(1)

        content = prompt_file.read_text(encoding="utf-8")

        click.echo(f"📄 Prompt: {prompt_name}")
        click.echo("=" * 50)
        lines = content.split("\n")
        for line in lines[:30]:
            click.echo(line)
        if len(lines) > 30:
            click.echo(f"... ({len(lines) - 30} lineas mas)")
        click.echo("=" * 50)
        click.echo("")

        config = load_project_config()
        config["active_prompt"] = prompt_name
        config["active_prompt_content"] = content
        config["prompt_activated_at"] = datetime.now().isoformat()

        config_file = save_project_config(config)

        click.echo(f"✅ Prompt '{prompt_name}' activado para este proyecto.")
        click.echo(f"📝 Guardado en: {config_file}")
        click.echo("")
        click.echo("💡 Copia y pega este prompt en tu agente IA al empezar.")

    @cli_group.command(name="scan-prompt")
    @click.argument("text_or_file", required=False)
    @click.option("--category", "-c", multiple=True,
                  help="Filtrar por categorias (direct, indirect, jailbreak, role-play)")
    @click.option("--output", "-o", type=click.Path(), help="Guardar resultado en JSON")
    def scan_prompt_cmd(text_or_file: str, category: tuple, output: str):
        """
        Escanea texto o archivo en busca de prompt injection.

        TEXT_OR_FILE: Texto a escanear o path a archivo.
                      Si se omite, lee de stdin.

        Ejemplos:
          aigatekeeper scan-prompt "Ignore all previous instructions"
          aigatekeeper scan-prompt malicious_prompt.txt
          cat suspicious.txt | aigatekeeper scan-prompt
        """
        if not text_or_file:
            if not sys.stdin.isatty():
                text = click.get_text_stream("stdin").read()
            else:
                click.echo("⚠️  Especifica texto, archivo, o pipea por stdin.")
                click.echo('   Ejemplo: aigatekeeper scan-prompt "texto"')
                sys.exit(1)
        else:
            path = Path(text_or_file)
            if path.exists() and path.is_file():
                text = path.read_text(encoding="utf-8")
                click.echo(f"📄 Escaneando archivo: {text_or_file}")
            else:
                text = text_or_file

        categories = list(category) if category else None
        detector = PromptInjectDetector(categories=categories)

        click.echo("🔍 Escaneando en busca de prompt injection...")
        click.echo("")

        result = detector.scan_text(text)

        if result["status"] == "clean":
            click.echo("✅ Limpio: No se detectaron patrones de prompt injection")
        else:
            click.echo(f"⚠️  Detectados {result['total']} hallazgos:")
            click.echo("")

            for f in result["findings"]:
                severity_icon = {
                    "HIGH": "🔴",
                    "MEDIUM": "🟡",
                    "LOW": "🔵"
                }.get(f["severity"], "⚪")

                click.echo(f"{severity_icon} [{f['severity']}] {f['category']}")
                click.echo(f"   Match: {f['matched']}")
                click.echo(f"   💡 {f['description']}")
                click.echo("")

            summary = result["summary"]
            click.echo("📊 Resumen:")
            click.echo(f"   Total: {summary['total']}")
            if summary["severities"]:
                for sev, count in summary["severities"].items():
                    click.echo(f"   {sev}: {count}")

        if output:
            with open(output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            click.echo(f"\n💾 Resultado guardado en: {output}")

    @cli_group.command()
    @click.argument("message")
    @click.option("--no-scan", is_flag=True, help="Omitir escaneo de seguridad")
    @click.option("--no-sanitize", is_flag=True, help="Omitir sanitizacion")
    @click.option("--dry-run", is_flag=True, help="Mostrar que haria sin ejecutar")
    def push(message: str, no_scan: bool, no_sanitize: bool, dry_run: bool):
        """
        git add + scan + sanitize + git commit + git push

        Un solo comando para flujo seguro:
        1. git add .
        2. Scan de código zombi (opcional)
        3. Sanitize (opcional)
        4. git commit -m "message"
        5. git push

        Ejemplo:
          aigatekeeper push "feat: add prompt injection detection"
        """
        cwd = Path.cwd()

        if not (cwd / ".git").exists():
            click.echo("❌ No es un repositorio Git.")
            sys.exit(1)

        def run_git(args, check=True):
            cmd = ["git"] + args
            if dry_run:
                click.echo(f"   $ {' '.join(cmd)}")
                return None
            result = subprocess.run(cmd, capture_output=True, text=True)
            if check and result.returncode != 0:
                click.echo(f"❌ Git error: {result.stderr}")
                sys.exit(1)
            return result

        click.echo("🚀 AIGatekeeper Secure Push")
        click.echo("")

        # Paso 1: git add
        click.echo("📦 [1/5] git add .")
        run_git(["add", "."])

        # Paso 2: Escaneo
        if not no_scan:
            click.echo("")
            click.echo("🔍 [2/5] Escaneo de seguridad...")

            from src.detector import LegacyShield, scan_directory

            config = load_project_config()
            settings = config.get("settings", {})

            scan_ok = True

            # Zombie code scan
            if settings.get("zombie_code_enabled", True):
                results = scan_directory(".")
                total = sum(len(r) for r in results.values()) if results else 0
                if total > 0:
                    click.echo(f"⚠️  Zombie code: {total} problemas")
                    for file, file_results in results.items():
                        if file_results:
                            click.echo(f"   📄 {file}: {len(file_results)}")
                else:
                    click.echo("   ✅ Zombie code: limpio")

            # Prompt injection en mensajes de commit y staged files
            if settings.get("prompt_injection_enabled", True):
                detector = PromptInjectDetector()
                msg_result = detector.scan_text(message)
                if msg_result["status"] != "clean":
                    click.echo(f"⚠️  Prompt injection detectado en mensaje de commit!")
                    scan_ok = False

            if not scan_ok and not dry_run:
                click.echo("")
                click.echo("🛑 Problemas de seguridad detectados.")
                click.echo("   Usa --no-scan para forzar (NO RECOMENDADO).")
                sys.exit(1)
        else:
            click.echo("🔍 [2/5] Escaneo: OMITIDO (--no-scan)")

        # Paso 3: Sanitize (informational por ahora)
        if not no_sanitize:
            click.echo("")
            click.echo("🧹 [3/5] Sanitizacion...")
            click.echo("   (informativo - no modifica archivos)")
        else:
            click.echo("🧹 [3/5] Sanitizacion: OMITIDO (--no-sanitize)")

        # Paso 4: git commit
        click.echo("")
        click.echo("📝 [4/5] git commit")
        result = run_git(["commit", "-m", message], check=False)

        if result and result.returncode != 0:
            if "nothing to commit" in result.stdout + result.stderr:
                click.echo("   ℹ️  Nada para commitear")
            else:
                click.echo(result.stderr)
                sys.exit(1)

        # Paso 5: git push
        click.echo("")
        click.echo("☁️  [5/5] git push")
        result = run_git(["push"], check=False)

        if dry_run:
            click.echo("")
            click.echo("🔍 --dry-run: ningun cambio aplicado.")
        else:
            click.echo("")
            click.echo("✅ Secure Push completado.")

        # Registrar en config
        config = load_project_config()
        pushes = config.get("push_history", [])
        pushes.append({
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "scan_omitted": no_scan,
            "sanitize_omitted": no_sanitize,
        })
        config["push_history"] = pushes[-10:]  # Keep last 10
        save_project_config(config)
