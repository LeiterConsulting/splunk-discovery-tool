"""
Discovery Tool for Splunk MCP Server (DT4SMS)
Main application entry point
Version: 1.0.0
"""

import uvicorn
import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from web_app import app, config_manager

def main():
    """Main entry point"""
    config = config_manager.get()
    
    print("=" * 60)
    print(" Discovery Tool for Splunk MCP Server (DT4SMS)")
    print(f" Version: {config.version}")
    print("=" * 60)
    print(f" Web Interface: http://localhost:{config.server.port}")
    print(f" Settings: Click gear icon in web interface")
    print("=" * 60)
    
    # Start server
    uvicorn.run(
        app,
        host=config.server.host,
        port=config.server.port,
        log_level="info"
    )

if __name__ == "__main__":
    main()
