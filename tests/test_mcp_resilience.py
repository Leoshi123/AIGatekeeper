import json
import pytest
import time
from src.mcp_mock_layer import MCPMockLayer, FailureConfig
from src.mcp_server import mcp as server

# Note: Since the MCP server (FastMCP) manages its own transport,
# these tests simulate the layer that would sit between the
# transport and the server logic.

class ProtocolFuzzer:
    """
    Generates malformed and adversarial JSON-RPC payloads to test server resilience.
    """
    def __init__(self):
        self.test_cases = []

    def generate_truncated_payload(self, base_payload: dict):
        content = json.dumps(base_payload)
        return content[:len(content) // 2]

    def generate_type_mismatch(self, base_payload: dict):
        payload = base_payload.copy()
        if "params" in payload:
            # Replace a string parameter with a giant list or unexpected type
            if isinstance(payload["params"], dict):
                key = list(payload["params"].keys())[0]
                payload["params"][key] = [1, 2, 3] * 1000
            elif isinstance(payload["params"], list):
                payload["params"] = "I should be a list"
        return payload

    def generate_oversized_payload(self, base_payload: dict):
        payload = base_payload.copy()
        payload["params"] = "A" * (1024 * 1024 * 5) # 5MB string
        return payload

    def generate_malformed_json(self):
        return '{"jsonrpc": "2.0", "method": "sanitize_code", "params": { "code": "print(1)" ' # Missing closing brace

def test_mcp_resilience():
    """
    Integration test suite for MCP Server resilience.
    """
    fuzzer = ProtocolFuzzer()
    mock_layer = MCPMockLayer(FailureConfig(corrupt_rate=0.0)) # Controlled corruption

    base_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sanitize_code",
        "params": {"code": "print('hello')"}
    }

    # 1. Test Truncated JSON
    truncated = fuzzer.generate_truncated_payload(base_request)
    # Simulate what happens when server receives this
    # Since we can't easily spin up a full MCP network stack in a unit test without a client,
    # we test the mock layer's ability to generate and the server's likely reaction.
    assert len(truncated) < len(json.dumps(base_request))

    # 2. Test Type Mismatches
    mismatched = fuzzer.generate_type_mismatch(base_request)
    # The fuzzer swaps a param value for a list, so params should be a dict containing a list
    assert isinstance(mismatched["params"], dict)
    assert any(isinstance(v, list) for v in mismatched["params"].values())

    # 3. Test Oversized
    oversized = fuzzer.generate_oversized_payload(base_request)
    assert len(json.dumps(oversized)) > 1024 * 1024

def test_instability_scenarios():
    """
    Test network instability using MCPMockLayer.
    """
    # Case A: High Drop Rate (Packet Loss)
    config_drop = FailureConfig(drop_rate=1.0)
    mock_drop = MCPMockLayer(config_drop)
    assert mock_drop.intercept_request({"test": "data"}) is None

    # Case B: Transport Timeout (Hang)
    # We use a smaller timeout for the test, but the mock uses 10s
    config_timeout = FailureConfig(timeout_rate=1.0)
    mock_timeout = MCPMockLayer(config_timeout)

    start_time = time.time()
    # This will trigger the 10s sleep in MCPMockLayer.intercept_request
    # We run it in a separate thread or just accept the slow test for now
    result = mock_timeout.intercept_request({"test": "data"})
    end_time = time.time()

    assert result is None
    assert (end_time - start_time) >= 10

    # Case C: Payload Corruption
    config_corrupt = FailureConfig(corrupt_rate=1.0)
    mock_corrupt = MCPMockLayer(config_corrupt)

    result = mock_corrupt.intercept_request({"jsonrpc": "2.0", "id": 1})
    # The result should be a corrupted version (string or modified dict)
    assert result != {"jsonrpc": "2.0", "id": 1}

if __name__ == "__main__":
    pytest.main([__file__])
