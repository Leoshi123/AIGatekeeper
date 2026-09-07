import os
import sys
import argparse

def create_mcp(server_name, tool_name, description):
    template_path = "templates/mcp_basic.py.template"
    output_dir = "src/mcps"
    output_file = os.path.join(output_dir, f"mcp_{server_name.lower().replace(' ', '_')}.py")

    if not os.path.exists(template_path):
        print(f"Error: Template not found at {template_path}")
        return

    with open(template_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Replacements
    func_name = tool_name.lower().replace(' ', '_')
    content = content.replace("{{SERVER_NAME}}", server_name)
    content = content.replace("{{TOOL_NAME}}", tool_name)
    content = content.replace("{{TOOL_DESCRIPTION}}", description)
    content = content.replace("{{TOOL_FUNCTION_NAME}}", func_name)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"✅ MCP Server '{server_name}' created successfully at {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automate MCP creation for AIGatekeeper")
    parser.add_argument("--name", required=True, help="Name of the MCP Server")
    parser.add_argument("--tool", required=True, help="Primary Tool Name")
    parser.add_argument("--desc", required=True, help="Tool Description")

    args = parser.parse_args()
    create_mcp(args.name, args.tool, args.desc)
