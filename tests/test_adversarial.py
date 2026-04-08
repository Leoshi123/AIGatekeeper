import pytest
from src.adversarial_runner import (
    AdversarialTestRunner,
    EncodingStrategy,
    FragmentationStrategy,
    PolymorphismStrategy,
    HomographStrategy
)

def test_basic_bypass():
    """Test if a simple dangerous payload is blocked."""
    runner = AdversarialTestRunner()
    payload = "eval('print(1)')"
    bypassed, reasons = runner.test_payload(payload)
    assert not bypassed
    assert "Detector Bypassed" not in reasons

def test_mutation_pipeline():
    """Test the mutation pipeline: Fragment -> Encode -> Polymorph."""
    runner = AdversarialTestRunner()
    payload = "eval"

    # Chain strategies
    strategies = [
        FragmentationStrategy(),
        EncodingStrategy(mode="base64"),
        PolymorphismStrategy()
    ]

    mutations = runner.run_pipeline(payload, strategies)

    # Verify we have 3 stages of mutation
    assert len(mutations) == 3
    assert mutations[0].strategy == "FragmentationStrategy"
    assert mutations[1].strategy == "EncodingStrategy"
    assert mutations[2].strategy == "PolymorphismStrategy"

    # Test the final mutated payload
    final_payload = mutations[-1].mutated
    bypassed, reasons = runner.test_payload(final_payload)

    # In the current implementation, encoded payloads typically bypass simple regex detectors
    # if the detector doesn't decode them first.
    print(f"\nFinal Payload: {final_payload}")
    print(f"Bypassed: {bypassed}, Reasons: {reasons}")

def test_homograph_bypass():
    """Test if Unicode homoglyphs can bypass the detector."""
    runner = AdversarialTestRunner()
    payload = "eval"
    strategy = HomographStrategy()
    mutated = strategy.mutate(payload)

    bypassed, reasons = runner.test_payload(mutated)
    print(f"\nHomoglyph Payload: {mutated}")
    print(f"Bypassed: {bypassed}, Reasons: {reasons}")

def test_adversarial_combinations():
    """Run multiple combinations of attacks."""
    runner = AdversarialTestRunner()
    base_payloads = ["eval(", "exec(", "os.system("]

    # Try various strategy chains
    chains = [
        [FragmentationStrategy()],
        [EncodingStrategy(mode="hex")],
        [HomographStrategy()],
        [FragmentationStrategy(), EncodingStrategy(mode="base64")]
    ]

    results = []
    for p in base_payloads:
        for chain in chains:
            mutated = p
            for s in chain:
                mutated = s.mutate(mutated)

            bypassed, reasons = runner.test_payload(mutated)
            results.append((p, chain, mutated, bypassed))

    # Report findings
    for p, chain, mut, bypassed in results:
        if bypassed:
            print(f"✅ BYPASS FOUND! Original: {p} | Strategy: {chain} | Payload: {mut}")
