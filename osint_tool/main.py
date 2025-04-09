#!/usr/bin/env python3
"""
OSINT CLI Tool - A comprehensive OSINT tool for terminal use
Author: Anonymous
License: MIT
"""

import os
import sys
import click
from rich.console import Console
from rich.panel import Panel
from dotenv import load_dotenv

# Load modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from osint_tool.config import initialize_config

# Import all modules
try:
    from osint_tool.modules.people import people_search
    from osint_tool.modules.ip_geo import ip_lookup
    from osint_tool.modules.domain import domain_intel
    from osint_tool.modules.image import image_analysis
    from osint_tool.modules.threat import threat_intel
    from osint_tool.modules.github import github_intel
    from osint_tool.modules.utils import export_utils, extra_utils
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

# Initialize console
console = Console()


@click.group()
@click.version_option("1.0.0")
def cli():
    """
    OSINT CLI Tool - A comprehensive open source intelligence tool using free APIs.
    
    This tool provides multiple OSINT capabilities including username search, 
    IP lookup, domain intelligence, image analysis, threat intelligence, and more.
    """
    # Load environment variables
    load_dotenv()
    # Initialize configuration
    initialize_config()
    
    # Display banner
    console.print(
        Panel.fit(
            "[bold cyan]OSINT CLI Tool[/bold cyan] - [bold green]v1.0.0[/bold green]\n"
            "[italic]A free, powerful OSINT CLI-based tool[/italic]",
            border_style="blue",
        )
    )


# Register command groups
cli.add_command(people_search.people_commands)
cli.add_command(ip_lookup.ip_commands)
cli.add_command(domain_intel.domain_commands)
cli.add_command(image_analysis.image_commands)
cli.add_command(threat_intel.threat_commands)
cli.add_command(github_intel.github_commands)
cli.add_command(extra_utils.utils_commands)


if __name__ == "__main__":
    cli() 