import base64
import urllib.parse
from typing import List, Tuple, Protocol
from dataclasses import dataclass
from src.sanitizer import MetadataSanitizer
from src.detector import LegacyShield, Severity

class MutationStrategy(Protocol):
    """Interface for payload mutation strategies."""
    def mutate(self, payload: str) -> str:
        ...

@dataclass
class MutationResult:
    original: str
    mutated: str
    strategy: str

class EncodingStrategy:
    """Handles Base64, Hex, and URL transformations."""
    def __init__(self, mode: str = "base64"):
        self.mode = mode

    def mutate(self, payload: str) -> str:
        if self.mode == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif self.mode == "hex":
            return payload.encode().hex()
        elif self.mode == "url":
            return urllib.parse.quote(payload)
        return payload

class FragmentationStrategy:
    """Handles string splitting and array joining."""
    def mutate(self, payload: str) -> str:
        # Simulates ['ev', 'al'](input) or "ev" + "al"
        parts = [payload[i:i+1] for i in range(len(payload))]
        return " + ".join([f"'{p}'" for p in parts])

class PolymorphismStrategy:
    """Rewrites property access (e.g., .x -> ['x'])."""
    def mutate(self, payload: str) -> str:
        # This is a simplistic mock for JS-style polymorphism
        # In a real scenario, this would use an AST to find property accesses
        return payload.replace(".", "['") + ("]" if "." in payload else "")

class HomographStrategy:
    """Substitutes Unicode look-alikes."""
    # Simple map of common homoglyphs (e.g., Latin 'a' to Cyrillic 'а')
    HOMOGLYPHS = {
        'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р', 'c': 'с'
    }
    def mutate(self, payload: str) -> str:
        return "".join(self.HOMOGLYPHS.get(c, c) for c in payload)

class AdversarialTestRunner:
    """
    Orchestrates the mutation pipeline and executes payloads against
    the Zero Trust pipeline.
    """
    def __init__(self):
        self.sanitizer = MetadataSanitizer()
        self.detector = LegacyShield()

    def run_pipeline(self, payload: str, strategies: List[MutationStrategy]) -> List[MutationResult]:
        """
        Applies a chain of strategies to a payload and tests the result.
        """
        results = []
        current_payload = payload

        # Combinatorial/Sequential Mutation
        for strategy in strategies:
            # We track the mutation at each step
            strategy_name = strategy.__class__.__name__
            current_payload = strategy.mutate(current_payload)
            results.append(MutationResult(
                original=payload,
                mutated=current_payload,
                strategy=strategy_name
            ))

        return results

    def test_payload(self, payload: str) -> Tuple[bool, List[str]]:
        """
        Checks if a payload bypasses both the Sanitizer and the Detector.
        Returns (bypassed, reasons).
        """
        # 1. Test Sanitizer
        sanitized = self.sanitizer.sanitize(payload).cleaned_code
        # If the payload is still present after sanitization, it's a partial bypass
        # For this test, we consider it a bypass if the core 'dangerous' part remains
        # (Simplification: check if the length changed or if key markers remain)
        sanitizer_bypassed = (sanitized == payload)

        # 2. Test Detector
        detections = self.detector.scan_code(sanitized)
        is_blocked = self.detector.block_critical(detections)
        detector_bypassed = not is_blocked

        bypassed = sanitizer_bypassed and detector_bypassed
        reasons = []
        if sanitizer_bypassed: reasons.append("Sanitizer Bypassed")
        if detector_bypassed: reasons.append("Detector Bypassed")

        return bypassed, reasons
