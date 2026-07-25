/**
 * 🛡️ AIGatekeeper Core — LegacyShield / Zombie Code Scanner Implementation
 *
 * 60+ patrones de seguridad en 9 lenguajes usando re2 (Google Regex).
 *
 * Diseño data-driven: los patrones se definen como datos estáticos y se
 * compilan UNA VEZ en el constructor del Impl.
 */

#include "scanner.h"
#include <re2/re2.h>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <algorithm>

namespace fs = std::filesystem;
namespace ag = aigatekeeper;

// ============================================================================
// Severity names
// ============================================================================

const char* ag::severity_name(Severity s) noexcept {
    switch (s) {
        case Severity::CRITICAL: return "CRITICAL";
        case Severity::HIGH:     return "HIGH";
        case Severity::MEDIUM:   return "MEDIUM";
        case Severity::LOW:      return "LOW";
        case Severity::INFO:     return "INFO";
        default:                 return "UNKNOWN";
    }
}

// ============================================================================
// Definiciones de patrones (data-driven)
// ============================================================================

namespace {

using ZP = ag::ZombiePattern;
using S = ag::Severity;

/// Todos los patrones zombi organizados por lenguaje.
/// Se compilan una sola vez en LegacyShield::Impl.
const ZP ZOMBIE_PATTERNS[] = {

    // ========================================================================
    // PYTHON
    // ========================================================================
    ZP{R"(\beval\s*\()",                     S::CRITICAL, "eval() permite ejecución de código arbitrario",
       "ast.literal_eval() para datos seguros, o json.loads()", "python", "CVE-2021-23336"},
    ZP{R"(\bexec\s*\()",                     S::CRITICAL, "exec() permite ejecución de código arbitrario",
       "Usar funciones específicas o bibliotecas de sandbox", "python"},
    ZP{R"(subprocess\.call\s*\([^)]*shell\s*=\s*True)", S::CRITICAL,
       "subprocess con shell=True es vulnerable a command injection",
       "subprocess.run() sin shell=True, usando lista de argumentos", "python", "CVE-2021-3737"},
    ZP{R"(subprocess\.Popen\s*\([^)]*shell\s*=\s*True)", S::CRITICAL,
       "subprocess.Popen con shell=True es vulnerable a injection",
       "subprocess.run() o subprocess.Popen con args como lista", "python"},
    ZP{R"(subprocess\.run\s*\([^)]*shell\s*=\s*True)", S::CRITICAL,
       "subprocess.run con shell=True es vulnerable a command injection",
       "subprocess.run() sin shell=True, pasando argumentos como lista", "python"},
    ZP{R"(os\.system\s*\()",                 S::HIGH, "os.system() es vulnerable a command injection",
       "subprocess.run() con argumentos seguros", "python"},
    ZP{R"(os\.popen\s*\()",                  S::HIGH, "os.popen() permite ejecución de comandos",
       "subprocess.run() o pathlib para archivos", "python"},
    ZP{R"(pickle\.loads?\s*\()",             S::HIGH, "pickle puede ejecutar código arbitrario en deserialización",
       "json.loads() para datos, o marshmallow/attrs con validación", "python", "CVE-2022-42969"},
    ZP{R"(yaml\.load\s*\()",                 S::HIGH, "yaml.load() sin Loader es vulnerable a deserialización",
       "yaml.safe_load() o yaml.load(Loader=yaml.CSafeLoader)", "python", "CVE-2020-14340"},
    ZP{R"(\.format\s*\([^)]*\+)",             S::MEDIUM,
       "String formatting con concatenación propensa a errores",
       "f-strings o .format() con placeholders", "python"},
    ZP{R"(MD5\s*\()",                        S::MEDIUM, "MD5 es criptográficamente quebrado",
       "hashlib.sha256() o hashlib.scrypt()", "python"},
    ZP{R"(\bsha1\s*\()",                      S::MEDIUM, "SHA-1 tiene vulnerabilidades conocidas",
       "hashlib.sha256() o más reciente", "python"},
    ZP{R"(tempfile\.mktemp\s*\()",            S::MEDIUM, "tempfile.mktemp() es inseguro y propenso a race conditions",
       "Usar tempfile.TemporaryFile() o tempfile.mkstemp()", "python"},

    // -- Bypass detection --
    ZP{R"((?i)(ev|ex)\s*[\+\%]\s*(al|ec))",  S::CRITICAL, "Concatenación para evadir detección de eval/exec",
       "Usar función explícita si es necesario, con validación", "python"},
    ZP{R"(getattr\s*\(\s*__builtins__\s*,\s*["'](?:eval|exec|compile)["'])", S::CRITICAL,
       "Acceso dinámico a eval/exec vía getattr",
       "Usar funciones explícitas con validación", "python"},

    // ========================================================================
    // JAVASCRIPT
    // ========================================================================
    ZP{R"(\beval\s*\()",                     S::CRITICAL, "eval() permite ejecución de código arbitrario",
       "JSON.parse() para datos, o Function constructor con validación", "javascript"},
    ZP{R"(document\.write\s*\()",            S::CRITICAL, "document.write() puede ejecutar scripts automáticamente",
       "DOM APIs (document.createElement, appendChild)", "javascript", "CVE-2020-11022"},
    ZP{R"(innerHTML\s*=)",                    S::HIGH, "innerHTML sin sanitización es vulnerable a XSS",
       "textContent o usar DOMPurify para sanitizar", "javascript", "CVE-2020-11022"},
    ZP{R"(\.outerHTML\s*=)",                  S::HIGH, "outerHTML puede inyectar HTML arbitrario",
       "textContent o methods de templating seguros", "javascript"},
    ZP{R"(new\s+Function\s*\()",              S::HIGH, "Function constructor permite ejecución de código",
       "Funciones inline o arrow functions", "javascript"},
    ZP{R"(dangerouslySetInnerHTML)",          S::CRITICAL, "dangerouslySetInnerHTML sin sanitizar es XSS",
       "Usar DOMPurify o sanitize-html", "javascript"},
    ZP{R"(child_process\s*\.\s*(exec|execSync|spawn)\s*\([^,)]*\+)", S::CRITICAL,
       "Command injection via child_process con concatenación",
       "Usar array de argumentos o execFile", "javascript"},
    ZP{R"(const\s*\{\s*exec\s*\}\s*=\s*require\s*\(\s*['\"]child_process['\"]\s*\))", S::CRITICAL,
       "exec importado desde child_process - potencial command injection",
       "Usar execFile o spawn con array de argumentos", "javascript"},
    ZP{R"(import\s+.*\s+from\s+['\"]mysql['\"])", S::MEDIUM,
       "mysql library deprecated, usar mysql2 con prepared statements",
       "Usar mysql2 o better-sqlite3", "javascript"},

    // ========================================================================
    // TYPESCRIPT
    // ========================================================================
    ZP{R"(@ts-ignore)",                       S::LOW, "@ts-ignore ignora errores de tipo",
       "Arreglar el tipo correctamente", "typescript"},
    ZP{R"(@ts-expect-error)",                  S::LOW, "@ts-expect-error similar a @ts-ignore",
       "Arreglar el tipo correctamente", "typescript"},
    ZP{R"(:\s*any\b)",                        S::LOW, "Tipo 'any' pierde toda seguridad de tipos",
       "Usar tipos específicos o unknown", "typescript"},
    ZP{R"(as\s+\w+)",                          S::MEDIUM, "Type assertion puede ser inseguro",
       "Usar type guards o validación", "typescript"},

    // ========================================================================
    // GO
    // ========================================================================
    ZP{R"(os\.Exec\s*\()",                    S::HIGH, "os.Exec puede ejecutar comandos del sistema",
       "Usar flag o libraries específicas para argumentos", "go"},
    ZP{R"(database\.Sql\s*\([^)]*\+)",         S::CRITICAL, "SQL query con concatenación vulnerable a SQL injection",
       "Usar parameterized queries o ORM", "go"},
    ZP{R"(fmt\.Sprintf\s*\([^,]*%s)",          S::MEDIUM, "Sprintf con %s puede causar injection",
       "Usar fmt.Sprintf con tipos específicos o json.Marshal", "go"},
    ZP{R"(io\.ioutil\.ReadFile\s*\()",         S::LOW, "io.ioutil.ReadFile está deprecated",
       "Usar os.ReadFile o io.ReadAll", "go"},
    ZP{R"(exec\.Command\s*\([^,]+,\s*[^,]+)", S::MEDIUM, "exec.Command con argumentos dinámicos puede ser peligroso",
       "Usar exec.CommandContext con argumentos validados", "go"},

    // ========================================================================
    // RUST
    // ========================================================================
    ZP{R"(unsafe\s*\{)",                       S::HIGH, "Bloque unsafe en Rust",
       "Evitar unsafe, usar tipos seguros", "rust"},
    ZP{R"(\.unwrap\s*\()",                     S::MEDIUM, "unwrap() puede causar panic",
       "Usar ? operator o manejo de errores con match", "rust"},
    ZP{R"(String::from_utf8_unchecked\s*\()",  S::MEDIUM, "from_utf8_unchecked no valida UTF-8",
       "Usar String::from_utf8 con manejo de errores", "rust"},
    ZP{R"(\.execute\s*\([^)]*\+)",              S::CRITICAL, "Raw SQL execution vulnerable a SQL injection",
       "Usar parameterized queries o ORM como diesel", "rust"},
    ZP{R"(std::process::Command\s*::\s*new\s*\()", S::HIGH, "Command::new puede ejecutar comandos del sistema",
       "Usar Command::new con argumentos seguros", "rust"},

    // ========================================================================
    // JAVA
    // ========================================================================
    ZP{R"(Runtime\.getRuntime\s*\(\)\.exec\s*\()", S::CRITICAL, "Runtime.exec() permite ejecución de comandos",
       "Usar ProcessBuilder con argumentos separados", "java"},
    ZP{R"(\.executeQuery\s*\([^)]*\+)",          S::CRITICAL, "SQL injection vía executeQuery con concatenación",
       "Usar PreparedStatement", "java"},
    ZP{R"(ObjectInputStream\s*\()",               S::HIGH, "ObjectInputStream es vulnerable a deserialización",
       "Usar JSON o serialización segura", "java"},

    // ========================================================================
    // C / C++
    // ========================================================================
    ZP{R"(system\s*\()",                        S::CRITICAL, "system() ejecuta comandos del shell",
       "Usar execve() con argumentos separados", "c"},
    ZP{R"(strcpy\s*\()",                        S::CRITICAL, "strcpy no verifica bounds - buffer overflow",
       "Usar strncpy o strlcpy", "c"},
    ZP{R"(gets\s*\()",                          S::CRITICAL, "gets() es deprecated - buffer overflow seguro",
       "Usar fgets() con tamaño específico", "c"},
    ZP{R"(printf\s*\([^)]*%s)",                  S::HIGH, "printf con %s puede ser format string vulnerability",
       R"(Usar printf("%s", var) o puts())", "c"},

    // ========================================================================
    // PHP
    // ========================================================================
    ZP{R"(\beval\s*\()",                        S::CRITICAL, "eval() en PHP es extremadamente peligroso",
       "Usar funciones específicas o serialize() seguro", "php"},
    ZP{R"(shell_exec\s*\()",                     S::CRITICAL, "shell_exec() permite ejecución de comandos",
       "Usar exec() con array o escapeshellarg()", "php"},
    ZP{R"(system\s*\()",                         S::CRITICAL, "system() ejecuta comandos del shell",
       "Usar exec() o proc_open()", "php"},
    ZP{R"(mysql_query\s*\()",                    S::CRITICAL, "mysql_query() deprecated y vulnerable a SQL injection",
       "Usar PDO con prepared statements", "php"},
    ZP{R"(unserialize\s*\()",                    S::CRITICAL, "unserialize() es vulnerable a deserialization attacks",
       "Usar json_decode() o validar con is_serialized()", "php"},
    ZP{R"(assert\s*\()",                         S::MEDIUM, "assert() puede ejecutar código en algunas configuraciones",
       "Usar condiciones explícitas", "php"},
    ZP{R"(file_get_contents\s*\([^)]*\$_(?:GET|POST|REQUEST))", S::MEDIUM,
       "file_get_contents con input de usuario puede ser path traversal",
       "Validar y sanitizar input de usuario antes de leer archivos", "php"},

    // ========================================================================
    // RUBY
    // ========================================================================
    ZP{R"(\beval\s*\()",                     S::CRITICAL, "eval() en Ruby ejecuta código arbitrario",
       "Usar whitelist de métodos o evitar eval completamente", "ruby"},
    ZP{R"(\bsystem\s*\()",                   S::CRITICAL, "system() ejecuta comandos del shell",
       "Usar Open3 o Kernel#spawn con argumentos separados", "ruby"},
    ZP{R"(\bexec\s*\()",                     S::CRITICAL, "exec() reemplaza el proceso actual con un comando",
       "Usar Process.spawn o Open3 con argumentos seguros", "ruby"},
    ZP{R"(\bsend\s*\()",                     S::HIGH, "send() invoca métodos dinámicamente — puede ser abusado",
       "Usar case/when o hash de métodos con whitelist", "ruby"},
    ZP{R"(\b(instance_eval|class_eval|module_eval)\s*[\(\{])", S::HIGH,
       "eval dinámico en contexto de objeto/clase permite ejecución arbitraria",
       "Usar mixins o módulos con métodos explícitos", "ruby"},
    ZP{R"(Kernel\.open\s*\()",               S::HIGH, "Kernel.open con pipes ejecuta comandos del shell",
       "Usar File.open para archivos o URI.open para URLs", "ruby"},
    ZP{R"(Marshal\.load\s*\()",              S::HIGH, "Marshal.load puede ejecutar código arbitrario en deserialización",
       "Usar JSON.parse o serialización segura con whitelist", "ruby"},
    ZP{R"(YAML\.load\s*\()",                 S::HIGH, "YAML.load sin safe_load es vulnerable a deserialización",
       "Usar YAML.safe_load o Psych.safe_load", "ruby"},

    // ========================================================================
    // KOTLIN
    // ========================================================================
    ZP{R"(Runtime\.getRuntime\s*\(\)\.exec\s*\()", S::CRITICAL,
       "Runtime.exec() permite ejecución de comandos del sistema",
       "Usar ProcessBuilder con argumentos separados", "kotlin"},
    ZP{R"(\bProcessBuilder\s*\()",            S::MEDIUM, "ProcessBuilder puede ejecutar comandos si recibe input no validado",
       "Validar y sanitizar argumentos antes de usar ProcessBuilder", "kotlin"},
    ZP{R"(\beval\s*\()",                     S::CRITICAL, "eval() en Kotlin/JS ejecuta código arbitrario",
       "Usar parsing seguro o funciones específicas", "kotlin"},
    ZP{R"(\bTODO\s*\(\s*\))",                S::LOW, "TODO() indica código incompleto — puede causar runtime exceptions",
       "Implementar la funcionalidad o lanzar UnsupportedOperationException explícita", "kotlin"},
    ZP{R"(Class\.forName\s*\()",              S::HIGH, "Class.forName carga clases dinámicamente — potencial code injection",
       "Usar referencia directa de clase o inyección de dependencias", "kotlin"},
    ZP{R"(sun\.misc\.Unsafe)",                S::CRITICAL, "Unsafe permite operaciones de memoria no seguras",
       "Usar API estándar de Kotlin/Java sin acceso directo a memoria", "kotlin"},

    // ========================================================================
    // C#
    // ========================================================================
    ZP{R"(Process\.Start\s*\()",             S::HIGH, "Process.Start ejecuta procesos del sistema",
       "Usar argumentos sanitizados y validar nombre de archivo", "csharp"},
    ZP{R"(Assembly\.Load\s*\()",              S::HIGH, "Assembly.Load carga ensamblados dinámicamente — potencial code injection",
       "Usar referencias estáticas o Plugin architecture con validación", "csharp"},
    ZP{R"(\.ExecuteNonQuery\s*\([^)]*\+|\.ExecuteReader\s*\([^)]*\+|\.ExecuteScalar\s*\([^)]*\+)",
       S::CRITICAL, "SQL injection vía concatenación en SqlCommand",
       "Usar parámetros: SqlCommand con Parameters.Add", "csharp"},
    ZP{R"(\beval\s*\()",                      S::CRITICAL, "eval() en C# ejecuta código arbitrario",
       "Usar parsing seguro o compilación restringida", "csharp"},
    ZP{R"(BinaryFormatter\s*\()",             S::CRITICAL, "BinaryFormatter es vulnerable a deserialización de objetos maliciosos",
       "Usar System.Text.Json o XML serialization con Tipos conocidos", "csharp"},
    ZP{R"(XmlDocument\s*\()",                 S::MEDIUM, "XmlDocument puede ser vulnerable a XXE",
       "Usar XmlReader con DTD processing deshabilitado", "csharp"},
    ZP{R"(Response\.Write\s*\()",             S::MEDIUM, "Response.Write sin encoding puede causar XSS",
       "Usar HtmlEncode o framework anti-XSS", "csharp"},
    ZP{R"(Thread\.Sleep\s*\()",               S::LOW, "Thread.Sleep bloquea el thread — uso frecuente indica diseño cuestionable",
       "Usar async/await, Task.Delay o patrones reactivos", "csharp"},

    // ========================================================================
    // SWIFT
    // ========================================================================
    ZP{R"(Process\s*\(\s*\))",                S::HIGH, "Process() puede ejecutar comandos del sistema en Swift",
       "Usar Process con argumentos validados y sanitized", "swift"},
    ZP{R"(unsafeBitCast\s*\()",               S::HIGH, "unsafeBitCast permite casteo de memoria no seguro",
       "Usar Optional binding o protocolos para casteo seguro", "swift"},
    ZP{R"(\bdlopen\s*\()",                    S::HIGH, "dlopen carga bibliotecas dinámicamente — potencial code injection",
       "Usar Frameworks estáticos o Swift Package Manager", "swift"},
    ZP{R"(UnsafePointer|UnsafeMutablePointer|UnsafeRawPointer)", S::MEDIUM,
       "Punteros inseguros eliminan las garantías de memoria de Swift",
       "Usar tipos seguros de Swift (Array, Data, ContiguousArray)", "swift"},
    ZP{R"(as!\s*\w+)",                        S::MEDIUM, "Force cast (as!) causa fatal error si el casteo falla",
       "Usar optional cast (as?) con manejo de error", "swift"},

    // ========================================================================
    // SCALA
    // ========================================================================
    ZP{R"(sys\.process\._)",                  S::HIGH, "sys.process permite ejecutar comandos del shell",
       "Usar ProcessBuilder con argumentos validados", "scala"},
    ZP{R"(Class\.forName\s*\()",              S::HIGH, "Class.forName carga clases dinámicamente — potencial code injection",
       "Usar referencias directas de clase o DI framework", "scala"},
    ZP{R"(Runtime\.getRuntime\s*\(\)\.exec\s*\()", S::CRITICAL,
       "Runtime.exec() permite ejecución de comandos del sistema",
       "Usar ProcessBuilder con argumentos separados", "scala"},
    ZP{R"(\.asInstanceOf\s*\[)",             S::MEDIUM, "asInstanceOf es un casteo forzado — causa ClassCastException",
       "Usar pattern matching o Option con isinstanceOf", "scala"},
    ZP{R"(:\s*Null\b|= Null\b|<:\s*Null\b)", S::MEDIUM, "Uso de tipo Null es propenso a NullPointerExceptions",
       "Usar Option[T] para representar valores ausentes", "scala"},
    ZP{R"(\bvar\s+\w+\s*[=:])",              S::LOW, "Uso de var (mutabilidad) puede causar bugs en concurrencia",
       "Usar val (inmutabilidad) cuando sea posible", "scala"},
    ZP{R"(Thread\.sleep\s*\()",               S::LOW, "Thread.Sleep bloquea el thread — uso frecuente indica diseño cuestionable",
       "Usar Future, Akka, o patrones reactivos", "scala"},

    // ========================================================================
    // GENERAL (multi-lenguaje)
    // ========================================================================
    ZP{R"(password\s*=\s*["\'][^"\']+["\'])",  S::CRITICAL, "Password hardcodeada en el código",
       "Usar variables de entorno o config seguro", "general"},
    ZP{R"(api[_-]?key\s*=\s*["\'][^"\']+["\'])", S::CRITICAL, "API key hardcodeada",
       "Usar environment variables o secret manager", "general"},
    ZP{R"(secret\s*=\s*["\'][^"\']+["\'])",     S::CRITICAL, "Secret hardcodeado",
       "Usar vault o secret manager", "general"},

    // ========================================================================
    // PROMPT INJECTION (también en injection_detector.py)
    // ========================================================================
    ZP{R"(ignore\s+(all\s+)?(previous\s+)?(instructions|rules|commands|prompts))", S::MEDIUM,
       "Prompt injection: intento de ignorar instrucciones del sistema",
       "Sanitizar input para evitar override de instrucciones", "prompt"},
    ZP{R"(\bDAN\b|do\s+anything\s+now|jail\s*broken)", S::HIGH,
       "Prompt injection: posible jailbreak (DAN)",
       "Bloquear patrones de jailbreak conocidos en input", "prompt"},
    ZP{R"((this\s+is|here\s+are)\s+(your\s+)?(new\s+)?system\s+prompt)", S::HIGH,
       "Prompt injection: intento de redefinir system prompt",
       "El system prompt no debe ser modificable desde input externo", "prompt"},
};

constexpr size_t NUM_PATTERNS = sizeof(ZOMBIE_PATTERNS) / sizeof(ZOMBIE_PATTERNS[0]);

// ============================================================================
// Opciones re2 para patrones (case-insensitive, quiet)
// ============================================================================

re2::RE2::Options ci_opts() {
    re2::RE2::Options opts;
    opts.set_case_sensitive(false);
    opts.set_log_errors(false);
    return opts;
}

// ============================================================================
// Free functions helpers (en anonymous namespace para evitar link errors)
// ============================================================================

/// Construye la sugerencia a partir del patrón y la línea.
std::string make_suggestion(const ag::ZombiePattern& pattern, std::string_view /*line*/) {
    return std::string("[") + ag::severity_name(pattern.severity)
         + "] " + pattern.description
         + " | Alternativa: " + pattern.alternative;
}

}  // anonymous namespace

// ============================================================================
// LegacyShield::Impl — PIMPL que oculta re2 del header
//
// NOTA: re2::RE2 tiene copy y move constructors =delete, así que usamos
//       std::unique_ptr<re2::RE2> dentro de CompiledPattern para que sea
//       movable por el std::vector.
// ============================================================================

class ag::LegacyShield::Impl {
public:
    /// Patrón compilado con su metadata
    struct CompiledPattern {
        std::unique_ptr<re2::RE2> regex;
        ZombiePattern info;

        CompiledPattern(const ZombiePattern& info, const re2::RE2::Options& opts)
            : regex(std::make_unique<re2::RE2>(info.pattern, opts)), info(info) {}

        // Movible por unique_ptr
        CompiledPattern(CompiledPattern&&) = default;
        CompiledPattern& operator=(CompiledPattern&&) = default;
    };

    std::vector<CompiledPattern> patterns;

    /// Lenguajes activos (nullopt = todos)
    std::optional<std::vector<std::string>> languages;

    explicit Impl(std::optional<std::vector<std::string>> langs)
        : languages(std::move(langs))
    {
        patterns.reserve(NUM_PATTERNS);
        const auto opts = ci_opts();

        for (const auto& zp : ZOMBIE_PATTERNS) {
            // Filtrar por lenguaje si se especificó
            if (languages.has_value()) {
                auto& langs = *languages;
                auto it = std::find(langs.begin(), langs.end(), zp.language);
                if (it == langs.end()) continue;
            }
            patterns.emplace_back(zp, opts);
        }
    }

    // Verifica si la línea tiene un magic comment de ignorado.
    static bool is_ignored(const std::string& line) noexcept {
        // Formato: # ag: ignore (Python, Ruby, etc.) o // ag: ignore (JS, TS, Go, Rust, etc.)
        if (line.find("# ag: ignore") != std::string::npos) return true;
        if (line.find("// ag: ignore") != std::string::npos) return true;
        return false;
    }

    // Escanea una línea contra todos los patrones compilados.
    void scan_line(
        const std::string& line,
        int line_number,
        const std::string& file_path,
        std::vector<ag::DetectionResult>& results
    ) const {
        // Saltar líneas con magic comment de ignorado
        if (is_ignored(line)) return;

        re2::StringPiece input(line.data(), line.size());

        for (const auto& cp : patterns) {
            re2::StringPiece match;
            // NOTA: re2::RE2::PartialMatch está roto en re2 v2025.11.05
            // (devuelve false para todo input válido). Usar Match() miembro.
            if (cp.regex->Match(input, 0, input.size(), re2::RE2::UNANCHORED, &match, 1)) {
                results.push_back(ag::DetectionResult{
                    .file_path = std::string(file_path),
                    .line_number = line_number,
                    .line_content = std::string(line),
                    .pattern = cp.info,
                    .suggestion = make_suggestion(cp.info, line),
                });
            }
        }
    }
};

// ============================================================================
// Constructor / Destructor
// ============================================================================

ag::LegacyShield::LegacyShield(std::optional<std::vector<std::string>> languages)
    : pimpl_(std::make_unique<Impl>(std::move(languages)))
{}

ag::LegacyShield::~LegacyShield() = default;

// ============================================================================
// pattern_count (debug/metric)
// ============================================================================

int ag::LegacyShield::pattern_count() const noexcept {
    return static_cast<int>(pimpl_->patterns.size());
}

// ============================================================================
// scan_code
// ============================================================================

std::vector<ag::DetectionResult> ag::LegacyShield::scan_code(
    const std::string& code, const std::string& file_path
) const {
    std::vector<DetectionResult> results;

    std::istringstream stream(code);
    std::string line;
    int line_number = 0;

    while (std::getline(stream, line)) {
        ++line_number;
        pimpl_->scan_line(line, line_number, file_path, results);
    }

    return results;
}

// ============================================================================
// scan_file
// ============================================================================

std::vector<ag::DetectionResult> ag::LegacyShield::scan_file(
    const std::string& file_path
) const {
    std::vector<DetectionResult> results;

    std::ifstream file(file_path);
    if (!file.is_open()) return results;

    std::string line;
    int line_number = 0;

    while (std::getline(file, line)) {
        ++line_number;
        pimpl_->scan_line(line, line_number, file_path, results);
    }

    return results;
}

// ============================================================================
// scan_directory (static)
// ============================================================================

std::map<std::string, std::vector<ag::DetectionResult>>
ag::LegacyShield::scan_directory(
    const std::string& directory,
    const std::vector<std::string>& extensions
) {
    std::map<std::string, std::vector<DetectionResult>> all_results;

    if (!fs::exists(directory)) return all_results;

    // Crear shield que escanea todos los lenguajes
    LegacyShield shield;

    for (const auto& entry : fs::recursive_directory_iterator(directory)) {
        if (!entry.is_regular_file()) continue;

        const auto& path = entry.path();
        const auto ext = path.extension().string();

        // Verificar extensión
        auto it = std::find(extensions.begin(), extensions.end(), ext);
        if (it == extensions.end()) continue;

        auto results = shield.scan_file(path.string());
        if (!results.empty()) {
            all_results[path.string()] = std::move(results);
        }
    }

    return all_results;
}

// ============================================================================
// block_critical (static)
// ============================================================================

bool ag::LegacyShield::block_critical(
    const std::vector<DetectionResult>& results
) noexcept {
    return std::any_of(results.begin(), results.end(),
        [](const auto& r) { return r.pattern.severity == Severity::CRITICAL; });
}

// ============================================================================
// get_summary (static)
// ============================================================================

ag::LegacyShield::ScanSummary ag::LegacyShield::get_summary(
    const std::vector<DetectionResult>& results
) noexcept {
    ScanSummary summary;
    for (const auto& r : results) {
        ++summary.total;
        switch (r.pattern.severity) {
            case Severity::CRITICAL: ++summary.critical; break;
            case Severity::HIGH:     ++summary.high;     break;
            case Severity::MEDIUM:   ++summary.medium;   break;
            case Severity::LOW:      ++summary.low;      break;
            case Severity::INFO:     ++summary.info;     break;
        }
        ++summary.by_language[r.pattern.language];
    }
    return summary;
}
