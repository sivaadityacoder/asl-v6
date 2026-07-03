"""
ASL V6 - MCP Client Integration
Provides a connection to local/remote Model Context Protocol (MCP) servers
to give the NVIDIA AI Reviewer deep context gathering capabilities.
"""
import os
import json
import asyncio
from typing import Any
import structlog

logger = structlog.get_logger(__name__)


class WorkspaceMCPServer:
    """
    A lightweight, embedded MCP-compatible server that exposes local workspace
    tools to the AI. In a full deployment, this could connect via stdio to 
    external MCP servers (like the official git or filesystem servers).
    """
    def __init__(self, workspace_root: str):
        self.workspace_root = workspace_root
        
    async def list_tools(self) -> list[dict[str, Any]]:
        """Return the tools available on this MCP server in OpenAI JSON schema format."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read the contents of a file in the repository to gain more context about a vulnerability.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "The relative path to the file in the repository."
                            }
                        },
                        "required": ["file_path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "list_directory",
                    "description": "List the files in a directory to understand project structure.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "dir_path": {
                                "type": "string",
                                "description": "The relative path to the directory (use '.' for root)."
                            }
                        },
                        "required": ["dir_path"]
                    }
                }
            }
        ]
        
    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """Execute a tool call and return the result as a string."""
        try:
            if name == "read_file":
                file_path = arguments.get("file_path", "")
                full_path = os.path.join(self.workspace_root, file_path)
                # Security check to prevent directory traversal out of workspace
                if not os.path.abspath(full_path).startswith(os.path.abspath(self.workspace_root)):
                    return "Error: Access denied outside workspace."
                
                if not os.path.exists(full_path):
                    return f"Error: File {file_path} not found."
                    
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    # Truncate if too large for context window
                    if len(content) > 15000:
                        content = content[:15000] + "\n...[truncated]..."
                    return content
                    
            elif name == "list_directory":
                dir_path = arguments.get("dir_path", ".")
                full_path = os.path.join(self.workspace_root, dir_path)
                if not os.path.abspath(full_path).startswith(os.path.abspath(self.workspace_root)):
                    return "Error: Access denied outside workspace."
                
                if not os.path.isdir(full_path):
                    return f"Error: Directory {dir_path} not found."
                    
                items = os.listdir(full_path)
                return "\n".join(items)
                
            else:
                return f"Error: Tool {name} not found."
                
        except Exception as e:
            logger.error("MCP tool execution failed", tool=name, error=str(e))
            return f"Error executing {name}: {str(e)}"


class MCPToolClient:
    """
    Client that manages the MCP servers and exposes them to the LLM.
    """
    def __init__(self, workspace_root: str | None = None):
        import tempfile
        self.workspace_root = workspace_root or tempfile.gettempdir()
        self.servers: list[WorkspaceMCPServer] = []
        
    async def connect(self):
        """Initialize connections to configured MCP servers."""
        # For this implementation, we spin up the embedded workspace server
        self.servers.append(WorkspaceMCPServer(self.workspace_root))
        logger.info("Connected to MCP servers", count=len(self.servers))
        
    async def get_all_tools(self) -> list[dict[str, Any]]:
        """Aggregate tools from all connected MCP servers."""
        all_tools = []
        for server in self.servers:
            all_tools.extend(await server.list_tools())
        return all_tools
        
    async def execute_tool_call(self, tool_call) -> dict[str, Any]:
        """Execute a tool call requested by the LLM."""
        function_name = tool_call.function.name
        try:
            arguments = json.loads(tool_call.function.arguments)
        except json.JSONDecodeError:
            arguments = {}
            
        logger.debug("Executing MCP tool", tool=function_name, args=arguments)
        
        # Route to the appropriate server (in this simple version, try all until one handles it)
        # A full MCP implementation would track which server owns which tool.
        result_text = f"Error: Tool {function_name} not found on any MCP server."
        for server in self.servers:
            tools = await server.list_tools()
            if any(t["function"]["name"] == function_name for t in tools):
                result_text = await server.call_tool(function_name, arguments)
                break
                
        return {
            "tool_call_id": tool_call.id,
            "role": "tool",
            "name": function_name,
            "content": result_text,
        }
