import base64
import urllib.parse
import unicodedata
import re

class CodeNormalizer:
    """
    Normalizes code to defeat obfuscation techniques including
    Base64, Hex, URL encoding, and Unicode homoglyphs.
    """

    def __init__(self, max_recursion=3):
        self.max_recursion = max_recursion
        # Pattern to find potential Base64 strings (simplified)
        self.b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        # Pattern to find Hex strings like \x41 or 0x41
        self.hex_pattern = re.compile(r'(?:\\x|0x)([0-9a-fA-F]{2})')

    def normalize(self, text: str) -> str:
        """
        Performs recursive normalization of the input text.
        """
        current_text = text
        for _ in range(self.max_recursion):
            previous_text = current_text

            # 1. Unicode Normalization (NFKC) to defeat homoglyphs
            current_text = unicodedata.normalize('NFKC', current_text)

            # 2. URL Decoding
            current_text = urllib.parse.unquote(current_text)

            # 3. Hex Decoding
            current_text = self.hex_pattern.sub(lambda m: chr(int(m.group(1), 16)), current_text)

            # 4. Base64 Decoding (Tries to find and decode B64 blocks)
            # Note: B64 decoding is risky as it can produce garbage;
            # we only replace if the result is printable.
            current_text = self._try_decode_b64(current_text)

            if current_text == previous_text:
                break

        return current_text

    def _try_decode_b64(self, text: str) -> str:
        # We look for blocks that look like Base64 and are of significant length
        # to avoid corrupting normal text.
        def replace_b64(match):
            candidate = match.group(0)
            if len(candidate) < 8: return candidate
            try:
                decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
                if decoded.isprintable() and len(decoded) > 0:
                    return decoded
            except Exception:
                pass
            return candidate

        return self.b64_pattern.sub(replace_b64, text)
