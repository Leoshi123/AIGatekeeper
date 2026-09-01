# Test file to verify MCP wrapper functionality
# This should be scanned/intercepted by the security wrapper

import os
import sys

def vulnerable_function():
    # Example of dangerous code that should be caught
    user_input = input("Enter command: ")
    os.system(user_input)  # This is dangerous!

def sql_injection_example():
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE id = " + input("User ID: ")

def hardcoded_secret():
    # Should detect hardcoded secrets
    api_key = "sk-1234567890abcdef"

if __name__ == "__main__":
    print("Testing security wrapper...")
    vulnerable_function()