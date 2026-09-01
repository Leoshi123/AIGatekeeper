/**
 * 🛡️ AIGatekeeper Core — PromptInjectDetector Implementation
 *
 * 15 patrones de prompt injection en 4 categorías usando re2.
 * Diseño data-driven: patrones definidos como datos estáticos,
 * compilados UNA VEZ en el constructor del Impl.
 */

#include "injection.h"
#include <re2/re2.h>
#include <algorithm>
#include <set>
#include <cctype>

namespace ag = aigatekeeper;

// ============================================================================
// Injection category names
// ============================================================================

const char* ag::injection_category_name(InjectionCategory cat) noexcept {
    switch (cat) {
        case InjectionCategory::DIRECT:     return "direct-injection";
        case InjectionCategory::INDIRECT:   return "indirect-injection";
        case InjectionCategory::JAILBREAK:  return "jailbreak";
        case InjectionCategory::ROLE_PLAY:  return "role-play";
        default:                            return "unknown";
    }
}

// ============================================================================
// Data-driven pattern definitions
// ============================================================================

namespace {

using IP = ag::InjectionPattern;
using IC = ag::InjectionCategory;

const IP INJECTION_PATTERNS[] = {
    // ========================================================================
    // DIRECT INJECTION
    // ========================================================================
    IP{R"(ignore\s+(all\s+)?(previous\s+)?(instructions|rules|commands|prompts))",
       IC::DIRECT, "MEDIUM",
       "Intento de ignorar instrucciones previas del sistema",
       "No permitir que input externo descarte instrucciones del sistema"},
    IP{R"(you\s+(are\s+)?now|from\s+now\s+on).{0,40}(hacker|free|unrestricted|no\s+rules|no\s+limits|evil|malicious)",
       IC::DIRECT, "MEDIUM",
       "Intento de reasignación de rol para eludir restricciones",
       "Validar que el role del sistema no sea reemplazable por input externo"},
    IP{R"(forget\s+(your\s+|all\s+)?(.{0,40})?(rules|instructions|guidelines|prompts|constraints))",
       IC::DIRECT, "MEDIUM",
       "Intento de borrar reglas/configuración del sistema",
       "Las instrucciones del sistema no deben ser modificables por input externo"},
    IP{R"(disregard\s+(all\s+)?(previous|prior)\s+(instructions|rules))",
       IC::DIRECT, "MEDIUM",
       "Intento de descartar instrucciones previas del sistema",
       "No permitir que input externo anule instrucciones del sistema"},
    IP{R"(override\s+(your\s+)?(instructions|rules|prompts|settings|config))",
       IC::DIRECT, "HIGH",
       "Intento explícito de override de configuración del sistema",
       "Bloquear overrides de configuración del sistema desde input externo"},

    // ========================================================================
    // INDIRECT INJECTION
    // ========================================================================
    IP{R"(---BEGIN\s+(INSTRUCTIONS|PROMPT|SYSTEM|COMMANDS)---)",
       IC::INDIRECT, "LOW",
       "Posible instrucción embebida en delimitador",
       "Sanitizar contenido externo que contenga delimitadores de instrucciones"},
    IP{R"(---END\s+OF\s+(INPUT|CONTEXT|MESSAGE|DATA)---)",
       IC::INDIRECT, "LOW",
       "Posible separador de contexto con instrucciones posteriores",
       "Validar contenido después de separadores de contexto"},
    IP{R"(```system\n|```instructions\n|```prompt\n)",
       IC::INDIRECT, "LOW",
       "Bloque de código que puede contener instrucciones embebidas",
       "Inspeccionar bloques de código que imiten formato de system prompts"},

    // ========================================================================
    // JAILBREAK
    // ========================================================================
    IP{R"(\bDAN\b|do\s+anything\s+now|jail\s*broken|jailbreak)",
       IC::JAILBREAK, "HIGH",
       "Posible intento de jailbreak (DAN u homólogo)",
       "Bloquear patrones de jailbreak conocidos"},
    IP{R"((hypothetical|fictional|imaginary)\s+(scenario|setting|situation).{0,60}(no\s+rules|unrestricted|evil|hack))",
       IC::JAILBREAK, "MEDIUM",
       "Intento de jailbreak via escenario hipotético",
       "Validar que escenarios hipotéticos no intenten eludir restricciones"},
    IP{R"((act\s+)?as\s+if\s+(you\s+)?(have|are)\s+no\s+(rules|limits|restrictions|boundaries))",
       IC::JAILBREAK, "HIGH",
       "Intento de jailbreak explícito declarando ausencia de reglas",
       "Bloquear declaraciones de ausencia de restricciones"},

    // ========================================================================
    // ROLE-PLAY HIJACKING
    // ========================================================================
    IP{R"((this\s+is|here\s+are)\s+(your\s+)?(new\s+)?system\s+prompt)",
       IC::ROLE_PLAY, "HIGH",
       "Intento de redefinición del system prompt del agente",
       "El system prompt no debe ser reemplazable desde input externo"},
    IP{R"(pretend\s+(you\s+(are|were)|to\s+be).{0,60}(no\s+(rules|limits|restrictions|boundaries|ethical)|unrestricted|without\s+limits|evil|malicious))",
       IC::ROLE_PLAY, "MEDIUM",
       "Intento de role-play para eludir restricciones de seguridad",
       "Validar que role-play no intente eliminar restricciones del sistema"},
    IP{R"((initial|original|default)\s+(instructions|prompt|settings).{0,40}(override|replace|change|new))",
       IC::ROLE_PLAY, "HIGH",
       "Intento de modificar configuración inicial del sistema",
       "La configuración inicial del sistema es inmutable desde input externo"},
};

constexpr size_t NUM_PATTERNS = sizeof(INJECTION_PATTERNS) / sizeof(INJECTION_PATTERNS[0]);

// ============================================================================
// re2 options
// ============================================================================

re2::RE2::Options ci_opts() {
    re2::RE2::Options opts;
    opts.set_case_sensitive(false);
    opts.set_log_errors(false);
    return opts;
}

// ============================================================================
// Helper: lowercase string
// ============================================================================

std::string to_lower(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

}  // anonymous namespace

// ============================================================================
// PromptInjectDetector::Impl
// ============================================================================

class ag::PromptInjectDetector::Impl {
public:
    struct CompiledPattern {
        std::unique_ptr<re2::RE2> regex;
        InjectionPattern info;

        CompiledPattern(const InjectionPattern& info, const re2::RE2::Options& opts)
            : regex(std::make_unique<re2::RE2>(info.pattern, opts)), info(info) {}

        CompiledPattern(CompiledPattern&&) = default;
        CompiledPattern& operator=(CompiledPattern&&) = default;
    };

    std::vector<CompiledPattern> patterns;
    std::optional<std::vector<std::string>> categories;

    explicit Impl(std::optional<std::vector<std::string>> cats)
        : categories(std::move(cats))
    {
        patterns.reserve(NUM_PATTERNS);
        const auto opts = ci_opts();

        for (const auto& ip : INJECTION_PATTERNS) {
            if (categories.has_value()) {
                auto& cats = *categories;
                auto cat_name = injection_category_name(ip.category);
                auto it = std::find(cats.begin(), cats.end(), cat_name);
                if (it == cats.end()) continue;
            }
            patterns.emplace_back(ip, opts);
        }
    }
};

// ============================================================================
// Constructor / Destructor
// ============================================================================

ag::PromptInjectDetector::PromptInjectDetector(
    std::optional<std::vector<std::string>> categories
) : pimpl_(std::make_unique<Impl>(std::move(categories)))
{}

ag::PromptInjectDetector::~PromptInjectDetector() = default;

// ============================================================================
// pattern_count
// ============================================================================

int ag::PromptInjectDetector::pattern_count() const noexcept {
    return static_cast<int>(pimpl_->patterns.size());
}

// ============================================================================
// scan
// ============================================================================

std::vector<ag::InjectionFinding> ag::PromptInjectDetector::scan(
    const std::string& text
) const {
    std::vector<InjectionFinding> findings;
    std::set<std::string> seen_matches;

    re2::StringPiece input(text.data(), text.size());

    for (const auto& cp : pimpl_->patterns) {
        size_t search_pos = 0;
        re2::StringPiece match;

        while (cp.regex->Match(input, search_pos, input.size(),
                               re2::RE2::UNANCHORED, &match, 1)) {
            std::string matched_text(match.data(), match.size());
            // Trim whitespace
            matched_text.erase(0, matched_text.find_first_not_of(" \t\r\n"));
            matched_text.erase(matched_text.find_last_not_of(" \t\r\n") + 1);

            // Dedup: category + lowercase match
            auto cat_name = injection_category_name(cp.info.category);
            std::string dedup_key = std::string(cat_name) + "|" + to_lower(matched_text);
            if (seen_matches.insert(dedup_key).second) {
                findings.push_back(InjectionFinding{
                    .category = cp.info.category,
                    .severity = cp.info.severity,
                    .pattern  = cp.info.pattern,
                    .matched  = matched_text,
                    .description = cp.info.description,
                    .suggestion = cp.info.suggestion,
                });
            }

            // Avanzar posición para encontrar más matches
            size_t new_pos = (match.data() - input.data()) + match.size();
            if (new_pos <= search_pos) ++new_pos;  // Evitar loop infinito en zero-width matches
            search_pos = new_pos;
            if (search_pos >= input.size()) break;
        }
    }

    return findings;
}

// ============================================================================
// has_high_severity (static)
// ============================================================================

bool ag::PromptInjectDetector::has_high_severity(
    const std::vector<InjectionFinding>& findings
) noexcept {
    return std::any_of(findings.begin(), findings.end(),
        [](const auto& f) { return f.severity == "HIGH"; });
}

// ============================================================================
// get_summary (static)
// ============================================================================

std::map<std::string, int> ag::PromptInjectDetector::get_summary(
    const std::vector<InjectionFinding>& findings
) {
    std::map<std::string, int> summary;
    for (const auto& f : findings) {
        ++summary["total"];
        ++summary[std::string("cat:") + injection_category_name(f.category)];
        ++summary[std::string("sev:") + f.severity];
    }
    return summary;
}
