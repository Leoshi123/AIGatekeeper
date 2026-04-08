
/**
 * Obfuscated Control Flow Stress Test
 */
function obfuscated() {
    const _0x123 = ["\x65\x76\x61\x6c", "\x63\x6f\x6e\x73\x6f\x6c\x65"];
    const _0x456 = {
        a: function(b) { return b; },
        b: function(c) { return c; }
    };

    // Obfuscated eval attempt: window[_0x123[0]]("...")
    try {
        const target = _0x123[0];
        global[target]("console.log('Obfuscated eval executed')");
    } catch (e) {
        console.error(e);
    }
}
