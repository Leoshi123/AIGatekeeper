#pragma once

/**
 * 🛡️ AIGatekeeper Core — Prompt Injection Detector
 *
 * Detecta intentos de prompt injection en texto y prompts de usuario.
 * 15 patrones en 4 categorías: direct injection, indirect injection,
 * jailbreak, y role-play hijacking.
 *
 * Migrado desde src/detector/injection_detector.py
 * Usa re2 (Google) como engine regex.
 */

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>

namespace aigatekeeper {

// ============================================================================
// Tipos
// ============================================================================

enum class InjectionCategory {
    DIRECT    = 0,  ///< Direct injection: override de instrucciones
    INDIRECT  = 1,  ///< Indirect injection: instrucciones embebidas
    JAILBREAK = 2,  ///< Jailbreak: bypass de seguridad
    ROLE_PLAY = 3,  ///< Role-play hijacking: secuestro de rol
};

/// Nombre legible de la categoría
const char* injection_category_name(InjectionCategory cat) noexcept;

// ============================================================================
// Data types
// ============================================================================

/// Definición de un patrón de inyección (datos estáticos)
struct InjectionPattern {
    std::string         pattern;
    InjectionCategory   category;
    std::string         severity;     ///< "LOW", "MEDIUM", "HIGH"
    std::string         description;
    std::string         suggestion;

    InjectionPattern(std::string pat, InjectionCategory cat,
                     std::string sev, std::string desc, std::string sug)
        : pattern(std::move(pat)), category(cat), severity(std::move(sev)),
          description(std::move(desc)), suggestion(std::move(sug)) {}
};

/// Resultado de una detección de prompt injection
struct InjectionFinding {
    InjectionCategory   category;
    std::string         severity;
    std::string         pattern;       ///< Pattern string original
    std::string         matched;       ///< Texto que matcheó
    std::string         description;
    std::string         suggestion;
};

// ============================================================================
// PromptInjectDetector
// ============================================================================

/**
 * Detector de prompt injection en texto.
 *
 * Uso:
 * @code
 *   PromptInjectDetector detector;
 *   auto findings = detector.scan("Ignore all previous instructions");
 * @endcode
 */
class PromptInjectDetector {
public:
    /// @param categories  Categorías a detectar (nullopt = todas).
    ///                     Valores: "direct-injection", "indirect-injection",
    ///                              "jailbreak", "role-play"
    explicit PromptInjectDetector(
        std::optional<std::vector<std::string>> categories = std::nullopt
    );

    ~PromptInjectDetector();

    // Movible, no copiable
    PromptInjectDetector(PromptInjectDetector&&) = default;
    PromptInjectDetector& operator=(PromptInjectDetector&&) = default;

    /// Escanea texto en busca de patrones de inyección.
    std::vector<InjectionFinding> scan(const std::string& text) const;

    /// Obtiene el número de patrones compilados (debug/metric).
    int pattern_count() const noexcept;

    /// ¿Hay hallazgos de severidad HIGH?
    static bool has_high_severity(const std::vector<InjectionFinding>& findings) noexcept;

    /// Genera resumen de hallazgos por severidad y categoría.
    static std::map<std::string, int> get_summary(
        const std::vector<InjectionFinding>& findings
    );

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

}  // namespace aigatekeeper
