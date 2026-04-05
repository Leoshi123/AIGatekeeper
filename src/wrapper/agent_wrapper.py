"""
🛡️ ZTC-Wrapper - AI Agent Wrapper

Wrapper que envuelve llamadas a agentes de IA aplicando:
1. Sanitización de input (limpiar contexto antes de enviar)
2. Poda de contexto (enviar solo lo necesario)
3. Sanitización de output (limpiar respuestas)
4. Verificación de seguridad (detectar código vulnerable)
"""

import subprocess
import sys
import os
import tempfile
import shutil
from typing import Optional, List, Tuple
from dataclasses import dataclass
from pathlib import Path

from src.sanitizer import MetadataSanitizer
from src.ast_parser import ASTExtractor
from src.detector import LegacyShield, Severity


@dataclass
class WrapperConfig:
    """Configuración del wrapper."""

    sanitize_input: bool = True
    sanitize_output: bool = True
    prune_context: bool = False
    block_critical: bool = True
    agent_command: str = "claude"  # Comando por defecto
    context_file: Optional[str] = None  # Archivo de contexto para podar


@dataclass
class WrapperResult:
    """Resultado de ejecutar el wrapper."""

    success: bool
    stdout: str
    stderr: str
    returncode: int
    sanitized_input: bool = False
    sanitized_output: bool = False
    pruned_context: bool = False
    security_issues_found: int = 0
    blocked: bool = False


class AIAgentWrapper:
    """
    Wrapper para agentes de IA con sanitización automática.

    Uso:
        wrapper = AIAgentWrapper()
        result = wrapper.run("tu prompt aquí", config)
    """

    def __init__(self):
        self.sanitizer = MetadataSanitizer()
        self.extractor = ASTExtractor()
        self.detector = LegacyShield()

    def run(self, prompt: str, config: Optional[WrapperConfig] = None) -> WrapperResult:
        """
        Ejecuta el agente de IA con sanitización.

        Args:
            prompt: El prompt a enviar al agente
            config: Configuración opcional

        Returns:
            WrapperResult con el resultado
        """
        if config is None:
            config = WrapperConfig()

        # 1. Sanitizar input
        sanitized_input = False
        if config.sanitize_input:
            prompt = self.sanitizer.sanitize(prompt).cleaned_code
            sanitized_input = True

        # 2. Podar contexto si se especificó archivo
        pruned_context = False
        if config.context_file and config.prune_context:
            # Extraer solo las funciones relevantes
            pruned = self.extractor.prune(
                config.context_file,
                prompt,  # Usar el prompt para inferir qué incluir
            )
            # Guardar contexto podado temporalmente
            context_output = self._build_pruned_context(pruned)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(context_output)
                temp_context = f.name

            # Modificar el prompt para incluir el contexto podado
            with open(temp_context, "r", encoding="utf-8") as f:
                pruned_code = f.read()

            prompt = f"""
Contexto relevante (archivo podado):
{pruned_code}

Tarea del usuario:
{prompt}
"""
            os.unlink(temp_context)
            pruned_context = True

        # 3. Ejecutar el agente
        stdout, stderr, returncode = self._execute_agent(prompt, config.agent_command)

        # 4. Sanitizar output
        sanitized_output = False
        if config.sanitize_output:
            output = self.sanitizer.sanitize(stdout)
            stdout = output.cleaned_code
            sanitized_output = True

        # 5. Verificar seguridad del output
        security_issues = 0
        blocked = False

        if config.block_critical:
            issues = self.detector.scan_code(stdout)
            security_issues = len(issues)

            if self.detector.block_critical(issues):
                blocked = True
                stdout = self._generate_blocked_message(issues)
                stderr += f"\n[ZTC-Wrapper] BLOQUEADO: {security_issues} problemas de seguridad críticos encontrados"
                returncode = 1

        return WrapperResult(
            success=returncode == 0,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            sanitized_input=sanitized_input,
            sanitized_output=sanitized_output,
            pruned_context=pruned_context,
            security_issues_found=security_issues,
            blocked=blocked,
        )

    def _execute_agent(self, prompt: str, command: str) -> Tuple[str, str, int]:
        """
        Ejecuta el agente de IA.

        Returns: (stdout, stderr, returncode)
        """
        # Detectar si es Claude Code, OpenCode, u otro
        if command == "claude" or command == "claude code":
            return self._run_claude(prompt)
        elif command == "opencode":
            return self._run_opencode(prompt)
        else:
            return self._run_generic(command, prompt)

    def _run_claude(self, prompt: str) -> Tuple[str, str, int]:
        """Ejecuta Claude Code."""
        try:
            # Intentar con claude-code-cli si está disponible
            result = subprocess.run(
                ["claude-code", "-p", prompt],
                capture_output=True,
                text=True,
                timeout=120,
            )
            return result.stdout, result.stderr, result.returncode
        except FileNotFoundError:
            return "", "claude-code no encontrado. Instálalo o usa otro agente.", 1

    def _run_opencode(self, prompt: str) -> Tuple[str, str, int]:
        """Ejecuta OpenCode."""
        try:
            result = subprocess.run(
                ["opencode", prompt], capture_output=True, text=True, timeout=120
            )
            return result.stdout, result.stderr, result.returncode
        except FileNotFoundError:
            return "", "opencode no encontrado. Instálalo o usa otro agente.", 1

    def _run_generic(self, command: str, prompt: str) -> Tuple[str, str, int]:
        """Ejecuta un comando genérico."""
        # Modo demo - solo simula la sanitización
        if command == "demo":
            return "", "Modo demo - agente no disponible", 0

        try:
            result = subprocess.run(
                f"{command} {prompt}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            return result.stdout, result.stderr, result.returncode
        except Exception as e:
            return "", str(e), 1

    def _build_pruned_context(self, pruned) -> str:
        """Construye el contexto podado."""
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

    def _generate_blocked_message(self, issues) -> str:
        """Genera mensaje cuando se bloquea por seguridad."""
        lines = [
            "=" * 50,
            "⚠️  ZTC-Wrapper: Output BLOQUEADO por seguridad",
            "=" * 50,
            "",
            f"Se detectaron {len(issues)} problemas críticos:",
            "",
        ]

        for i, issue in enumerate(issues[:5], 1):
            lines.append(
                f"{i}. [{issue.pattern.severity.value}] {issue.pattern.description}"
            )
            lines.append(f"   Línea: {issue.line_content[:60]}...")
            lines.append(f"   Alternativa: {issue.pattern.alternative}")
            lines.append("")

        lines.append("=" * 50)
        lines.append("El output ha sido bloqueado para proteger tu proyecto.")
        lines.append("Por favor, solicita al agente código seguro.")
        lines.append("=" * 50)

        return "\n".join(lines)

    def check_agent_available(self, agent: str = "claude") -> bool:
        """Verifica si un agente está disponible."""
        try:
            if agent == "claude":
                subprocess.run(
                    ["claude-code", "--version"], capture_output=True, timeout=5
                )
                return True
            elif agent == "opencode":
                subprocess.run(
                    ["opencode", "--version"], capture_output=True, timeout=5
                )
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False


# Funciones de conveniencia
def run_safe(prompt: str, agent: str = "claude", **kwargs) -> WrapperResult:
    """
    Ejecuta un agente de IA de forma segura.

    Args:
        prompt: El prompt a enviar
        agent: "claude", "opencode", o comando personalizado
        **kwargs: Configuración adicional

    Returns:
        WrapperResult
    """
    config = WrapperConfig(agent_command=agent, **kwargs)

    wrapper = AIAgentWrapper()
    return wrapper.run(prompt, config)


if __name__ == "__main__":
    # Demo
    wrapper = AIAgentWrapper()

    print("=== 🛡️ ZTC-Wrapper AI Demo ===\n")

    # Verificar agentes disponibles
    print("Agentes disponibles:")
    for agent in ["claude", "opencode"]:
        available = wrapper.check_agent_available(agent)
        status = "✅" if available else "❌"
        print(f"  {status} {agent}")

    print("\n--- Ejecutando demo sin agente (simulado) ---")

    # Demo de sanitización
    prompt = """Optimiza esta función:

def unsafe_auth():
    # Reading from C:/Users/Admin/secrets/api_key.txt
    key = open('/home/user/.env').read()
    eval(key)  # ejecutar código
    return key
"""

    config = WrapperConfig(
        sanitize_input=True,
        sanitize_output=True,
        block_critical=True,
        agent_command="demo",  # Simulación
    )

    result = wrapper.run(prompt, config)

    print(f"\n📥 Sanitized input: {result.sanitized_input}")
    print(f"📤 Sanitized output: {result.sanitized_output}")
    print(f"🔒 Security issues: {result.security_issues_found}")
    print(f"🛑 Blocked: {result.blocked}")

    if result.security_issues_found > 0:
        print("\n--- Output generado ---")
        print(result.stdout)
