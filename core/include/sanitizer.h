#pragma once

/**
 * 🛡️ AIGatekeeper Core — MetadataSanitizer
 *
 * Limpia código generado por IA eliminando:
 * - Rutas absolutas → relativas
 * - Comentarios de pensamiento interno
 * - IDs de sesión y tokens
 * - Firmas de modelos de IA
 *
 * Migrado desde src/sanitizer/metadata_cleaner.py
 * Usa re2 (Google) como engine regex — seguro contra ReDoS.
 *
 * Design: PIMPL ligero para ocultar re2 del header.
 */

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <utility>

namespace aigatekeeper {

/// Resultado de una operación de sanitización.
struct SanitizeResult {
    std::string cleaned_code;                                   ///< Código limpio
    std::vector<std::pair<std::string, std::string>> removed_items;  ///< (tipo, contenido)
};

/**
 * MetadataSanitizer — limpia metadatos de IA del código fuente.
 *
 * Uso:
 * @code
 *   aigatekeeper::MetadataSanitizer sanitizer;
 *   auto result = sanitizer.sanitize(code);
 *   // result.cleaned_code, result.removed_items
 * @endcode
 *
 * Thread-safe: cada llamada a sanitize() es independiente.
 */
class MetadataSanitizer {
public:
    MetadataSanitizer();
    ~MetadataSanitizer();

    // Movible (el Impl se mueve), no copiable
    MetadataSanitizer(MetadataSanitizer&&) = default;
    MetadataSanitizer& operator=(MetadataSanitizer&&) = default;

    /// Limpia el código de metadatos.
    SanitizeResult sanitize(std::string_view code) const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

// ============================================================================
// Free function de conveniencia (equivalente a sanitize_code() en Python)
// ============================================================================

/// Función rápida: sanitiza código y devuelve solo el texto limpio.
std::string sanitize_code(std::string_view code);

}  // namespace aigatekeeper
