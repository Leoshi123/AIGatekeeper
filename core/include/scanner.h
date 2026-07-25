#pragma once

/**
 * 🛡️ AIGatekeeper Core — LegacyShield / Zombie Code Scanner
 *
 * Detecta funciones obsoletas, vulnerables o peligrosas en el código.
 * 60+ patrones en 9 lenguajes con clasificación por severidad.
 *
 * Migrado desde src/detector/zombie_detector.py
 * Usa re2 (Google) como engine regex.
 */

#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <memory>
#include <optional>

namespace re2 {
class RE2;
}

namespace aigatekeeper {

// ============================================================================
// Tipos de severidad
// ============================================================================

enum class Severity {
    CRITICAL = 0,  ///< Vulnerabilidad explotable — bloquear output
    HIGH    = 1,   ///< Código peligroso — advertir
    MEDIUM  = 2,   ///< Deprecated o ineficiente — advertir
    LOW     = 3,   ///< Sugerencia de mejora — informar
    INFO    = 4,   ///< Información — ignorar por defecto
};

/// Convertir Severity a string (para output)
const char* severity_name(Severity s) noexcept;

// ============================================================================
// Pattern y resultado
// ============================================================================

/// Definición de un patrón zombi (datos estáticos)
struct ZombiePattern {
    std::string pattern;        ///< Regex pattern string (raw)
    Severity    severity;       ///< Nivel de severidad
    std::string description;    ///< Descripción del problema
    std::string alternative;    ///< Alternativa segura
    std::string language;       ///< Lenguaje: "python", "javascript", "general", etc.
    std::optional<std::string> cve_ref;  ///< Referencia CVE (si aplica)

    /// Constructor compacto (sin CVE)
    ZombiePattern(std::string  pat, Severity sev, std::string  desc,
                  std::string  alt, std::string  lang)
        : pattern(std::move(pat)), severity(sev), description(std::move(desc)),
          alternative(std::move(alt)), language(std::move(lang)) {}

    /// Constructor con CVE
    ZombiePattern(std::string  pat, Severity sev, std::string  desc,
                  std::string  alt, std::string  lang, std::string  cve)
        : pattern(std::move(pat)), severity(sev), description(std::move(desc)),
          alternative(std::move(alt)), language(std::move(lang)),
          cve_ref(std::move(cve)) {}
};

/// Resultado de una detección individual
struct DetectionResult {
    std::string file_path;       ///< Ruta del archivo
    int         line_number;     ///< Número de línea
    std::string line_content;    ///< Contenido de la línea
    ZombiePattern pattern;      ///< Patrón que coincidió (copia)
    std::string suggestion;     ///< Sugerencia formateada
};

// ============================================================================
// LegacyShield — Scanner principal
// ============================================================================

/**
 * LegacyShield — detector de código zombi.
 *
 * Uso:
 * @code
 *   LegacyShield shield({"python", "javascript"});
 *   auto results = shield.scan_code(code);
 *   if (shield.block_critical(results)) { ... }
 * @endcode
 */
class LegacyShield {
public:
    /// @param languages  Lista de lenguajes a escanear (std::nullopt = todos)
    explicit LegacyShield(std::optional<std::vector<std::string>> languages = std::nullopt);

    ~LegacyShield();

    // Movible, no copiable
    LegacyShield(LegacyShield&&) = default;
    LegacyShield& operator=(LegacyShield&&) = default;

    // ========================================================================
    // API pública
    // ========================================================================

    /// Número de patrones compilados activos (debug/metric).
    int pattern_count() const noexcept;

    /// Escanea código en memoria (como string).
    std::vector<DetectionResult> scan_code(
        const std::string& code,
        const std::string& file_path = "<inline>"
    ) const;

    /// Escanea un archivo en disco.
    std::vector<DetectionResult> scan_file(const std::string& file_path) const;

    /// Escanea un directorio recursivamente.
    /// NOTE: Keep extensions in sync with src/languages.py (single source of truth).
    static std::map<std::string, std::vector<DetectionResult>> scan_directory(
        const std::string& directory,
        const std::vector<std::string>& extensions = {
            ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".php",
            ".rb", ".kt", ".kts", ".cs", ".swift", ".scala"
        }
    );

    /// ¿Hay problemas críticos que bloquean?
    static bool block_critical(const std::vector<DetectionResult>& results) noexcept;

    /// Genera resumen: total, críticos, altos, etc.
    struct ScanSummary {
        int total = 0;
        int critical = 0;
        int high = 0;
        int medium = 0;
        int low = 0;
        int info = 0;
        std::map<std::string, int> by_language;
    };
    static ScanSummary get_summary(const std::vector<DetectionResult>& results) noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;

};

}  // namespace aigatekeeper
