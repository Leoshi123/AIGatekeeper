import json
import time
import random
import threading
from typing import Any, Dict, Optional, Union
from dataclasses import dataclass

@dataclass
class FailureConfig:
    drop_rate: float = 0.0  # Probability of dropping a packet (0.0 to 1.0)
    delay_range: tuple[float, float] = (0.0, 0.0)  # Min/Max delay in seconds
    corrupt_rate: float = 0.0  # Probability of corrupting payload (0.0 to 1.0)
    timeout_rate: float = 0.0  # Probability of simulating a timeout (0.0 to 1.0)

class MCPMockLayer:
    """
    Intercepts MCP transport calls and injects failures based on FailureConfig.
    This layer acts as a middleware between the MCP Client and the Server.
    """
    def __init__(self, config: Optional[FailureConfig] = None):
        self.config = config or FailureConfig()
        self.metrics = {
            "requests_handled": 0,
            "requests_dropped": 0,
            "requests_delayed": 0,
            "requests_corrupted": 0,
            "requests_timed_out": 0,
        }

    def intercept_request(self, request: Union[str, Dict[str, Any]]) -> Optional[Union[str, Dict[str, Any]]]:
        """
        Processes an outgoing request. Returns None if the request is dropped.
        """
        self.metrics["requests_handled"] += 1

        # 1. Simulate Connection Drop/Packet Loss
        if random.random() < self.config.drop_rate:
            self.metrics["requests_dropped"] += 1
            return None

        # 2. Simulate Network Lag/Timeout
        if self.config.delay_range[1] > 0:
            delay = random.uniform(*self.config.delay_range)
            time.sleep(delay)
            self.metrics["requests_delayed"] += 1

        # 3. Simulate Server Hang (Timeout)
        if random.random() < self.config.timeout_rate:
            self.metrics["requests_timed_out"] += 1
            # Simulate a hang by sleeping longer than the typical client timeout
            time.sleep(10)
            return None

        # 4. Simulate Payload Corruption (Fuzzing)
        if random.random() < self.config.corrupt_rate:
            self.metrics["requests_corrupted"] += 1
            return self._corrupt_payload(request)

        return request

    def intercept_response(self, response: Union[str, Dict[str, Any]]) -> Optional[Union[str, Dict[str, Any]]]:
        """
        Processes an incoming response. Returns None if the response is dropped.
        """
        if random.random() < self.config.drop_rate:
            self.metrics["requests_dropped"] += 1
            return None

        if random.random() < self.config.corrupt_rate:
            self.metrics["requests_corrupted"] += 1
            return self._corrupt_payload(response)

        return response

    def _corrupt_payload(self, payload: Union[str, Dict[str, Any]]) -> Union[str, Dict[str, Any]]:
        """
        Randomly corrupts the payload to test server/client resilience.
        """
        corruption_type = random.choice(["truncate", "type_swap", "oversize", "malformed"])

        # Convert to string for mutation if it's a dict
        content = json.dumps(payload) if isinstance(payload, dict) else payload

        if corruption_type == "truncate":
            # Cut off the end of the JSON string
            return content[:len(content) // 2]

        elif corruption_type == "type_swap":
            # If it's a dict, swap a value's type
            if isinstance(payload, dict):
                new_payload = payload.copy()
                for k, v in new_payload.items():
                    new_payload[k] = [v] if not isinstance(v, list) else "swapped_to_string"
                    break
                return new_payload
            return "not_a_json_rpc_object"

        elif corruption_type == "oversize":
            # Append a massive amount of garbage data
            return content + ("A" * 1024 * 1024 * 10) # 10MB of junk

        elif corruption_type == "malformed":
            # Break the JSON syntax
            return content.replace("{", "[[[").replace("}", "]]]")

        return payload

    def get_metrics(self):
        return self.metrics
