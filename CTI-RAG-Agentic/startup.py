#!/usr/bin/env python3
"""
Simple startup script for Azure App Service - No Containers
"""

import os
import sys
import subprocess

def main():
    """Main entry point for Azure App Service"""
    print("🚀 Starting CTI RAG Agentic System...")

    # Change to the correct directory
    os.chdir('/home/site/wwwroot')

    print(f"📁 Current directory: {os.getcwd()}")
    print(f"🐍 Python version: {sys.version}")

    # Start Streamlit directly (dependencies should already be installed)
    print("🌐 Starting Streamlit with Agentic System...")
    subprocess.run([
        sys.executable, "-m", "streamlit", "run", "agentic_app.py",
        "--server.port=8000",
        "--server.address=0.0.0.0",
        "--server.headless=true",
        "--server.enableXsrfProtection=false",
        "--browser.gatherUsageStats=false",
        "--global.developmentMode=false"
    ], check=True)

if __name__ == "__main__":
    main() 