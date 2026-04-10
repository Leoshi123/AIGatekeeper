#!/usr/bin/env python3
"""
🛡️ AG-Wrapper Web Dashboard

Interfaz web local para AG-Wrapper.
Ejecutar: python server.py
Acceder: http://localhost:4901
"""

import os
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Template
import uvicorn

# Fix encoding para Windows
import sys
import io

if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace"
        )
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer, encoding="utf-8", errors="replace"
        )
    except Exception:
        pass

# Importar módulos de AG-Wrapper
from src.sanitizer import MetadataSanitizer
from src.detector import LegacyShield, Severity
from src.ast_parser import ASTExtractor

# Configuración
APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "ag_history.db"
STATIC_DIR = APP_DIR / "static"
TEMPLATES_DIR = APP_DIR / "templates"

# Crear directorios si no existen
STATIC_DIR.mkdir(exist_ok=True)
TEMPLATES_DIR.mkdir(exist_ok=True)

# Inicializar app
app = FastAPI(
    title="AG-Wrapper Dashboard",
    description="Zero-Trust AI Agent Wrapper - Security Dashboard",
    version="1.0.3",
)


# Base de datos
def init_db():
    """Inicializa la base de datos SQLite."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            language TEXT,
            input_size INTEGER,
            output_size INTEGER,
            issues_found INTEGER,
            issues_critical INTEGER,
            issues_high INTEGER,
            issues_medium INTEGER,
            issues_low INTEGER,
            details TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()

# Dashboard HTML con HTMX - Estilo Engram
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ AG-Wrapper Dashboard</title>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap');
        
        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
            min-height: 100vh;
        }
        
        .mono {
            font-family: 'JetBrains Mono', monospace;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
        }
        
        .glow {
            box-shadow: 0 0 30px rgba(99, 102, 241, 0.3);
        }
        
        .stat-card {
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.2) 0%, rgba(139, 92, 246, 0.1) 100%);
        }
        
        .critical { color: #ef4444; }
        .high { color: #f97316; }
        .medium { color: #eab308; }
        .low { color: #22c55e; }
        
        .pulse {
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .scanner-line {
            background: linear-gradient(90deg, transparent, #6366f1, transparent);
            height: 2px;
            animation: scan 2s ease-in-out infinite;
        }
        
        @keyframes scan {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }
        
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.05);
        }
        
        ::-webkit-scrollbar-thumb {
            background: rgba(99, 102, 241, 0.5);
            border-radius: 4px;
        }
    </style>
</head>
<body class="text-white">
    <!-- Header -->
    <nav class="border-b border-white/10 bg-black/20 backdrop-blur-lg sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
            <div class="flex items-center gap-4">
                <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-2xl">
                    🛡️
                </div>
                <div>
                    <h1 class="text-xl font-bold">AG-Wrapper</h1>
                    <p class="text-xs text-gray-400">Zero-Trust AI Agent Security</p>
                </div>
            </div>
            <div class="flex items-center gap-6">
                <span class="px-3 py-1 rounded-full bg-green-500/20 text-green-400 text-sm">
                    <i class="fas fa-circle text-xs animate-pulse"></i> Online
                </span>
                <span class="mono text-sm text-gray-400">v1.0.3</span>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="max-w-7xl mx-auto px-6 py-8">
        <!-- Stats Grid -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <!-- Total Scans -->
            <div class="card stat-card p-6">
                <div class="flex items-center justify-between mb-4">
                    <i class="fas fa-shield-halved text-2xl text-indigo-400"></i>
                    <span class="text-3xl font-bold" id="total-scans">0</span>
                </div>
                <p class="text-gray-400 text-sm">Total Scans</p>
            </div>
            
            <!-- Issues Found -->
            <div class="card stat-card p-6">
                <div class="flex items-center justify-between mb-4">
                    <i class="fas fa-bug text-2xl text-red-400"></i>
                    <span class="text-3xl font-bold" id="total-issues">0</span>
                </div>
                <p class="text-gray-400 text-sm">Issues Found</p>
            </div>
            
            <!-- Critical -->
            <div class="card stat-card p-6">
                <div class="flex items-center justify-between mb-4">
                    <i class="fas fa-exclamation-triangle text-2xl text-red-500"></i>
                    <span class="text-3xl font-bold text-red-400" id="critical-issues">0</span>
                </div>
                <p class="text-gray-400 text-sm">Critical Issues</p>
            </div>
            
            <!-- Code Sanitized -->
            <div class="card stat-card p-6">
                <div class="flex items-center justify-between mb-4">
                    <i class="fas fa-code text-2xl text-green-400"></i>
                    <span class="text-3xl font-bold" id="code-sanitized">0</span>
                </div>
                <p class="text-gray-400 text-sm">Lines Sanitized</p>
            </div>
        </div>

        <!-- Scanner Section -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
            <!-- Code Scanner -->
            <div class="card p-6">
                <h2 class="text-lg font-semibold mb-4 flex items-center gap-2">
                    <i class="fas fa-magnifying-glass text-indigo-400"></i>
                    Code Scanner
                </h2>
                
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm text-gray-400 mb-2">Language</label>
                        <select id="language" class="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-2 focus:outline-none focus:border-indigo-500">
                            <option value="python">Python</option>
                            <option value="javascript">JavaScript</option>
                            <option value="typescript">TypeScript</option>
                            <option value="go">Go</option>
                            <option value="rust">Rust</option>
                            <option value="java">Java</option>
                            <option value="c">C/C++</option>
                        </select>
                    </div>
                    
                    <div>
                        <label class="block text-sm text-gray-400 mb-2">Code to Analyze</label>
                        <textarea 
                            id="code-input" 
                            class="mono w-full h-48 bg-black/30 border border-white/10 rounded-lg px-4 py-2 focus:outline-none focus:border-indigo-500 resize-none"
                            placeholder="Paste your code here..."
                        ></textarea>
                    </div>
                    
                    <div class="flex gap-3">
                        <button 
                            hx-post="/api/scan"
                            hx-vals="javascript:document.getElementById('scan-params').value"
                            hx-include="[id='language'], [id='code-input']"
                            hx-target="#scan-results"
                            class="flex-1 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 px-6 py-3 rounded-lg font-semibold transition-all"
                        >
                            <i class="fas fa-scan"></i> Scan Code
                        </button>
                        
                        <button 
                            hx-post="/api/sanitize"
                            hx-include="[id='code-input']"
                            hx-target="#scan-results"
                            class="px-6 py-3 rounded-lg bg-white/10 hover:bg-white/20 border border-white/10 transition-all"
                        >
                            <i class="fas fa-broom"></i> Sanitize
                        </button>
                    </div>
                </div>
                
                <!-- Results Area -->
                <div id="scan-results" class="mt-4 min-h-[200px]">
                    <div class="flex items-center justify-center h-full text-gray-500">
                        <p>Scan results will appear here...</p>
                    </div>
                </div>
            </div>

            <!-- Quick Actions -->
            <div class="space-y-6">
                <!-- Pattern Stats -->
                <div class="card p-6">
                    <h2 class="text-lg font-semibold mb-4 flex items-center gap-2">
                        <i class="fas fa-chart-pie text-indigo-400"></i>
                        Detection by Language
                    </h2>
                    
                    <div class="space-y-3" id="lang-stats">
                        <div class="flex items-center justify-between">
                            <span class="flex items-center gap-2"><i class="fab fa-python text-yellow-400"></i> Python</span>
                            <span class="mono text-indigo-400">24 patterns</span>
                        </div>
                        <div class="flex items-center justify-between">
                            <span class="flex items-center gap-2"><i class="fab fa-js text-yellow-400"></i> JavaScript</span>
                            <span class="mono text-indigo-400">12 patterns</span>
                        </div>
                        <div class="flex items-center justify-between">
                            <span class="flex items-center gap-2"><i class="fab fa-golang text-cyan-400"></i> Go</span>
                            <span class="mono text-indigo-400">6 patterns</span>
                        </div>
                        <div class="flex items-center justify-between">
                            <span class="flex items-center gap-2"><i class="fab fa-rust text-orange-400"></i> Rust</span>
                            <span class="mono text-indigo-400">5 patterns</span>
                        </div>
                        <div class="flex items-center justify-between">
                            <span class="flex items-center gap-2"><i class="fab fa-java text-red-400"></i> Java</span>
                            <span class="mono text-indigo-400">4 patterns</span>
                        </div>
                        <div class="flex items-center justify-between">
                            <span class="flex items-center gap-2"><i class="fas fa-code text-blue-400"></i> C/C++</span>
                            <span class="mono text-indigo-400">4 patterns</span>
                        </div>
                    </div>
                </div>

                <!-- Recent Activity -->
                <div class="card p-6">
                    <h2 class="text-lg font-semibold mb-4 flex items-center gap-2">
                        <i class="fas fa-clock-rotate-left text-indigo-400"></i>
                        Recent Activity
                    </h2>
                    
                    <div id="history-list" class="space-y-2 max-h-48 overflow-y-auto">
                        <p class="text-gray-500 text-sm text-center py-4">No recent activity</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- API Info -->
        <div class="card p-6">
            <h2 class="text-lg font-semibold mb-4 flex items-center gap-2">
                <i class="fas fa-plug text-indigo-400"></i>
                API Endpoints
            </h2>
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div class="bg-black/20 rounded-lg p-4">
                    <code class="text-green-400">POST /api/scan</code>
                    <p class="text-gray-400 text-sm mt-2">Detect vulnerabilities in code</p>
                </div>
                <div class="bg-black/20 rounded-lg p-4">
                    <code class="text-green-400">POST /api/sanitize</code>
                    <p class="text-gray-400 text-sm mt-2">Remove AI metadata</p>
                </div>
                <div class="bg-black/20 rounded-lg p-4">
                    <code class="text-green-400">GET /api/stats</code>
                    <p class="text-gray-400 text-sm mt-2">Dashboard statistics</p>
                </div>
            </div>
        </div>
    </main>

    <!-- Footer -->
    <footer class="border-t border-white/10 bg-black/20 py-6 mt-12">
        <div class="max-w-7xl mx-auto px-6 text-center text-gray-500 text-sm">
            <p>🛡️ AG-Wrapper v1.0.3 | Built with ❤️ for the community</p>
        </div>
    </footer>

    <!-- Hidden inputs for HTMX -->
    <input type="hidden" id="scan-params" name="params" value="{}">

    <script>
        // Update stats on load
        document.addEventListener('DOMContentLoaded', async () => {
            try {
                const response = await fetch('/api/stats');
                const stats = await response.json();
                
                document.getElementById('total-scans').textContent = stats.total_scans || 0;
                document.getElementById('total-issues').textContent = stats.total_issues || 0;
                document.getElementById('critical-issues').textContent = stats.critical_issues || 0;
                document.getElementById('code-sanitized').textContent = stats.lines_sanitized || 0;
            } catch (e) {
                console.log('Stats not available');
            }
        });
    </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Dashboard principal."""
    return DASHBOARD_HTML


@app.get("/api/stats")
async def get_stats():
    """Obtiene estadísticas del dashboard."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Total scans
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE action = 'scan'")
    total_scans = cursor.fetchone()[0] or 0

    # Total issues
    cursor.execute("SELECT SUM(issues_found) FROM scan_history")
    total_issues = cursor.fetchone()[0] or 0

    # Critical issues
    cursor.execute("SELECT SUM(issues_critical) FROM scan_history")
    critical_issues = cursor.fetchone()[0] or 0

    # Lines sanitized
    cursor.execute(
        "SELECT SUM(output_size) FROM scan_history WHERE action = 'sanitize'"
    )
    lines_sanitized = cursor.fetchone()[0] or 0

    conn.close()

    return JSONResponse(
        {
            "total_scans": total_scans,
            "total_issues": total_issues,
            "critical_issues": critical_issues,
            "lines_sanitized": lines_sanitized,
        }
    )


@app.post("/api/scan")
async def scan_code(request: Request):
    """Escanea código en busca de vulnerabilidades."""
    form = await request.form()
    code = form.get("code-input", "")
    language = form.get("language", "python")

    if not code:
        return HTMLResponse("""
        <div class="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400">
            <i class="fas fa-exclamation-circle"></i> Please enter code to scan
        </div>
        """)

    try:
        shield = LegacyShield(languages=[language])
        results = shield.scan_code(code)

        if not results:
            return HTMLResponse("""
            <div class="bg-green-500/20 border border-green-500/50 rounded-lg p-4">
                <i class="fas fa-check-circle text-green-400"></i>
                <span class="text-green-400 ml-2">No issues found! Your code looks safe.</span>
            </div>
            """)

        # Guardar en historial
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        critical = sum(1 for r in results if r.pattern.severity == Severity.CRITICAL)
        high = sum(1 for r in results if r.pattern.severity == Severity.HIGH)
        medium = sum(1 for r in results if r.pattern.severity == Severity.MEDIUM)
        low = sum(1 for r in results if r.pattern.severity == Severity.LOW)

        cursor.execute(
            """
            INSERT INTO scan_history (timestamp, action, language, input_size, issues_found, 
            issues_critical, issues_high, issues_medium, issues_low, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                datetime.now().isoformat(),
                "scan",
                language,
                len(code),
                len(results),
                critical,
                high,
                medium,
                low,
                json.dumps(
                    [
                        {"line": r.line_number, "issue": r.pattern.description}
                        for r in results
                    ]
                ),
            ),
        )

        conn.commit()
        conn.close()

        # Generar HTML de resultados
        severity_colors = {
            Severity.CRITICAL: "bg-red-500/20 border-red-500 text-red-400",
            Severity.HIGH: "bg-orange-500/20 border-orange-500 text-orange-400",
            Severity.MEDIUM: "bg-yellow-500/20 border-yellow-500 text-yellow-400",
            Severity.LOW: "bg-green-500/20 border-green-500 text-green-400",
        }

        issues_html = "".join(
            [
                f"""
            <div class="border-l-4 {severity_colors.get(r.pattern.severity, "border-gray-500")} rounded-r-lg p-3 mb-2">
                <div class="flex items-start justify-between">
                    <div>
                        <span class="text-xs font-semibold uppercase">{r.pattern.severity.value}</span>
                        <p class="text-sm mt-1">{r.pattern.description}</p>
                        <p class="mono text-xs text-gray-500 mt-1">Line {r.line_number}: {r.line_content[:50]}...</p>
                    </div>
                    <i class="fas fa-exclamation-triangle text-lg opacity-50"></i>
                </div>
            </div>
            """
                for r in results[:10]
            ]
        )

        return HTMLResponse(f"""
        <div class="space-y-2">
            <div class="flex items-center gap-2 mb-4">
                <i class="fas fa-bug text-red-400 text-xl"></i>
                <span class="font-semibold">{len(results)} issues found</span>
            </div>
            {issues_html}
            {"<p class='text-gray-500 text-sm'>...and more</p>" if len(results) > 10 else ""}
        </div>
        """)

    except Exception as e:
        return HTMLResponse(f"""
        <div class="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400">
            <i class="fas fa-exclamation-circle"></i> Error: {str(e)}
        </div>
        """)


@app.post("/api/sanitize")
async def sanitize_code(request: Request):
    """Sanitiza código eliminando metadata de IA."""
    form = await request.form()
    code = form.get("code-input", "")

    if not code:
        return HTMLResponse("""
        <div class="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400">
            <i class="fas fa-exclamation-circle"></i> Please enter code to sanitize
        </div>
        """)

    try:
        sanitizer = MetadataSanitizer()
        result = sanitizer.sanitize(code)

        # Guardar en historial
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO scan_history (timestamp, action, input_size, output_size, issues_found, details)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                datetime.now().isoformat(),
                "sanitize",
                len(code),
                len(result.cleaned_code),
                len(result.removed_items),
                json.dumps(result.removed_items),
            ),
        )

        conn.commit()
        conn.close()

        return HTMLResponse(f"""
        <div class="space-y-4">
            <div class="flex items-center gap-2 mb-4">
                <i class="fas fa-check-circle text-green-400 text-xl"></i>
                <span class="font-semibold">Sanitization complete</span>
            </div>
            <div class="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
                <p class="text-sm text-green-400">
                    <i class="fas fa-eraser mr-2"></i>
                    Removed {len(result.removed_items)} items
                </p>
            </div>
            <div class="bg-black/30 rounded-lg p-3">
                <pre class="mono text-xs text-gray-300 overflow-x-auto max-h-32">{result.cleaned_code[:500]}</pre>
            </div>
        </div>
        """)

    except Exception as e:
        return HTMLResponse(f"""
        <div class="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400">
            <i class="fas fa-exclamation-circle"></i> Error: {str(e)}
        </div>
        """)


@app.get("/api/history")
async def get_history():
    """Obtiene historial de scans."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT timestamp, action, language, issues_found, issues_critical 
        FROM scan_history 
        ORDER BY id DESC 
        LIMIT 20
    """)

    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return JSONResponse([])

    return JSONResponse(
        [
            {
                "timestamp": row[0],
                "action": row[1],
                "language": row[2],
                "issues": row[3],
                "critical": row[4],
            }
            for row in rows
        ]
    )


if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║     🛡️ AG-Wrapper Dashboard v1.0.3                       ║
    ║     Zero-Trust AI Agent Security                         ║
    ╠═══════════════════════════════════════════════════════════╣
    ║                                                           ║
    ║   🌐 Server:  http://localhost:4901                      ║
    ║   📡 API:     http://localhost:4901/api                  ║
    ║   📖 Docs:    http://localhost:4901/docs (Swagger)        ║
    ║                                                           ║
    ║   Presiona Ctrl+C para detener                           ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    uvicorn.run(app, host="0.0.0.0", port=4901, reload=False)
