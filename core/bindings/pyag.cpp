/**
 * 🛡️ AIGatekeeper Core — Python Bindings (pybind11)
 *
 * Expone el core C++ a Python como módulo nativo `pyagcore`.
 * Los módulos Python existentes (CLI, MCP) importan esto como:
 *   from pyagcore import MetadataSanitizer, sanitize_code
 *
 * Migración progresiva: cada módulo C++ se agrega aquí.
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>   // para std::vector <-> list, std::pair <-> tuple
#include "sanitizer.h"
#include "scanner.h"
#include "injection.h"
#include <re2/re2.h>

namespace py = pybind11;
namespace ag = aigatekeeper;

// ============================================================================
// Binding del módulo Python `pyagcore`
// ============================================================================

PYBIND11_MODULE(pyagcore, m) {
    m.doc() = "AIGatekeeper Core Engine — C++ backend nativo";
    m.attr("__version__") = "2.0.0-dev";

    // ---- MetadataSanitizer ----

    py::class_<ag::SanitizeResult>(m, "SanitizeResult",
        "Resultado de sanitización con código limpio y lista de items removidos.")
        .def_readonly("cleaned_code", &ag::SanitizeResult::cleaned_code)
        .def_readonly("removed_items", &ag::SanitizeResult::removed_items)
        .def("__repr__", [](const ag::SanitizeResult& r) {
            return "<SanitizeResult cleaned=" + std::to_string(r.cleaned_code.size())
                 + " bytes, removed=" + std::to_string(r.removed_items.size()) + " items>";
        });

    py::class_<ag::MetadataSanitizer>(m, "MetadataSanitizer",
        "Limpiador de metadatos para código generado por IA.\n\n"
        "Elimina rutas absolutas, comentarios de IA, tokens de sesión,\n"
        "y firmas de modelos. Implementación C++ con re2 (Google Regex).")
        .def(py::init<>())
        .def("sanitize", &ag::MetadataSanitizer::sanitize,
            py::arg("code"),
            "Limpia el código de metadatos.\n\n"
            "Args:\n"
            "    code: Código original generado por IA (str).\n\n"
            "Returns:\n"
            "    SanitizeResult con cleaned_code y removed_items."
        );

    // ---- Severity enum ----
    py::enum_<ag::Severity>(m, "Severity", "Severidad de un hallazgo de seguridad.")
        .value("CRITICAL", ag::Severity::CRITICAL)
        .value("HIGH",     ag::Severity::HIGH)
        .value("MEDIUM",   ag::Severity::MEDIUM)
        .value("LOW",      ag::Severity::LOW)
        .value("INFO",     ag::Severity::INFO);

    // ---- ZombiePattern ----
    py::class_<ag::ZombiePattern>(m, "ZombiePattern",
        "Definición de un patrón de código zombi detectado.")
        .def_readonly("pattern",      &ag::ZombiePattern::pattern)
        .def_readonly("severity",     &ag::ZombiePattern::severity)
        .def_readonly("description",  &ag::ZombiePattern::description)
        .def_readonly("alternative",  &ag::ZombiePattern::alternative)
        .def_readonly("language",     &ag::ZombiePattern::language)
        .def_readonly("cve_ref",      &ag::ZombiePattern::cve_ref)
        .def("__repr__", [](const ag::ZombiePattern& zp) {
            return "<ZombiePattern [" + std::string(ag::severity_name(zp.severity))
                 + "] " + zp.description + " [" + zp.language + "]>";
        });

    // ---- DetectionResult ----
    py::class_<ag::DetectionResult>(m, "DetectionResult",
        "Resultado individual de una detección de código zombi.")
        .def_readonly("file_path",     &ag::DetectionResult::file_path)
        .def_readonly("line_number",   &ag::DetectionResult::line_number)
        .def_readonly("line_content",  &ag::DetectionResult::line_content)
        .def_readonly("pattern",       &ag::DetectionResult::pattern)
        .def_readonly("suggestion",    &ag::DetectionResult::suggestion)
        .def("__repr__", [](const ag::DetectionResult& r) {
            return "<DetectionResult " + r.file_path + ":" + std::to_string(r.line_number)
                 + " [" + std::string(ag::severity_name(r.pattern.severity)) + "]>";
        });

    // ---- ScanSummary ----
    py::class_<ag::LegacyShield::ScanSummary>(m, "ScanSummary",
        "Resumen de escaneo de código zombi.")
        .def_readonly("total",       &ag::LegacyShield::ScanSummary::total)
        .def_readonly("critical",    &ag::LegacyShield::ScanSummary::critical)
        .def_readonly("high",        &ag::LegacyShield::ScanSummary::high)
        .def_readonly("medium",      &ag::LegacyShield::ScanSummary::medium)
        .def_readonly("low",         &ag::LegacyShield::ScanSummary::low)
        .def_readonly("info",        &ag::LegacyShield::ScanSummary::info)
        .def_readonly("by_language", &ag::LegacyShield::ScanSummary::by_language)
        .def("__repr__", [](const ag::LegacyShield::ScanSummary& s) {
            return "<ScanSummary " + std::to_string(s.total) + " total"
                 + " (critical=" + std::to_string(s.critical)
                 + ", high=" + std::to_string(s.high)
                 + ", medium=" + std::to_string(s.medium)
                 + ", low=" + std::to_string(s.low)
                 + ", info=" + std::to_string(s.info) + ")>";
        });

    // ---- InjectionCategory enum ----
    py::enum_<ag::InjectionCategory>(m, "InjectionCategory",
        "Categoría de prompt injection.")
        .value("DIRECT",     ag::InjectionCategory::DIRECT)
        .value("INDIRECT",   ag::InjectionCategory::INDIRECT)
        .value("JAILBREAK",  ag::InjectionCategory::JAILBREAK)
        .value("ROLE_PLAY",  ag::InjectionCategory::ROLE_PLAY);

    // ---- InjectionFinding ----
    py::class_<ag::InjectionFinding>(m, "InjectionFinding",
        "Resultado de detección de prompt injection.")
        .def_readonly("category",    &ag::InjectionFinding::category)
        .def_readonly("severity",    &ag::InjectionFinding::severity)
        .def_readonly("pattern",     &ag::InjectionFinding::pattern)
        .def_readonly("matched",     &ag::InjectionFinding::matched)
        .def_readonly("description", &ag::InjectionFinding::description)
        .def_readonly("suggestion",  &ag::InjectionFinding::suggestion)
        .def("__repr__", [](const ag::InjectionFinding& f) {
            return "<InjectionFinding " + std::string(ag::injection_category_name(f.category))
                 + " [" + f.severity + "] '" + f.matched + "'>";
        });

    // ---- PromptInjectDetector ----
    py::class_<ag::PromptInjectDetector>(m, "PromptInjectDetector",
        "Detector de prompt injection en texto.\n\n"
        "Uso:\n"
        "    detector = PromptInjectDetector()\n"
        "    findings = detector.scan(texto)\n"
        "    if PromptInjectDetector.has_high_severity(findings):\n"
        "        print('🔴 Posible prompt injection detectada')")
        .def(py::init<std::optional<std::vector<std::string>>>(),
             py::arg("categories") = py::none())
        .def("pattern_count", &ag::PromptInjectDetector::pattern_count)
        .def("scan", &ag::PromptInjectDetector::scan, py::arg("text"))
        .def_static("has_high_severity", &ag::PromptInjectDetector::has_high_severity,
             py::arg("findings"))
        .def_static("get_summary", &ag::PromptInjectDetector::get_summary,
             py::arg("findings"));

    // ---- LegacyShield ----
    py::class_<ag::LegacyShield>(m, "LegacyShield",
        "Detector de código zombi. Escanea archivos por patrones de\n"
        "funciones obsoletas, vulnerables o peligrosas.\n\n"
        "Uso:\n"
        "    shield = LegacyShield()  # todos los lenguajes\n"
        "    results = shield.scan_code(código)\n"
        "    if LegacyShield.block_critical(results):\n"
        "        print('🔴 Código bloqueado por vulnerabilidades críticas')")
        .def(py::init<std::optional<std::vector<std::string>>>(), py::arg("languages") = py::none())
        .def("pattern_count",  &ag::LegacyShield::pattern_count)
        .def("scan_code",      &ag::LegacyShield::scan_code,
             py::arg("code"), py::arg("file_path") = "<inline>")
        .def("scan_file",      &ag::LegacyShield::scan_file, py::arg("file_path"))
        // NOTE: Keep extensions in sync with src/languages.py (single source of truth).
        .def_static("scan_directory",    &ag::LegacyShield::scan_directory,
             py::arg("directory"),
             py::arg("extensions") = std::vector<std::string>{
                ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".php",
                ".rb", ".kt", ".kts", ".cs", ".swift", ".scala"
             })
        .def_static("block_critical",    &ag::LegacyShield::block_critical,
             py::arg("results"))
        .def_static("get_summary",       &ag::LegacyShield::get_summary,
             py::arg("results"));

    // Free function de conveniencia
    m.def("sanitize_code", &ag::sanitize_code,
        py::arg("code"),
        "Limpia código rápido (singleton interno).\n\n"
        "Args:\n"
        "    code: Código a sanitizar.\n\n"
        "Returns:\n"
        "    Código limpio como string."
    );
}
