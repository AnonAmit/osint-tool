"""
IP and Geolocation module for OSINT CLI Tool.
Includes IP lookup, whois, and geolocation information.
"""

import re
import json
import socket
import ipaddress
import subprocess

import click
import requests
import whois
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from osint_tool.config import get_api_key, get_setting
from osint_tool.modules.utils import export_utils

console = Console()

# Define the Click command group
@click.group(name="ip")
def ip_commands():
    """Commands for IP and geolocation lookups."""
    pass


@ip_commands.command(name="lookup")
@click.argument("ip_address")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
@click.option("--provider", "-p", type=click.Choice(["ip-api", "ipinfo", "all"]), default="all", help="IP lookup provider")
def lookup_ip(ip_address, save, format, provider):
    """
    Look up information about an IP address.
    
    IP_ADDRESS: The IP address to look up.
    """
    # Validate IP address
    try:
        if not is_valid_ip(ip_address):
            # Try to resolve hostname to IP
            try:
                ip_info = socket.getaddrinfo(ip_address, None)
                ip_address = ip_info[0][4][0]
                console.print(f"[yellow]Resolved hostname to IP: [bold]{ip_address}[/bold][/yellow]")
            except socket.gaierror:
                console.print(f"[red]Invalid IP address or hostname: {ip_address}[/red]")
                return
    except ValueError:
        console.print(f"[red]Invalid IP address: {ip_address}[/red]")
        return
    
    console.print(f"[bold]Looking up IP: [cyan]{ip_address}[/cyan][/bold]")
    
    results = {}
    
    # IP-API.com lookup (free, no API key required)
    if provider in ["ip-api", "all"]:
        ip_api_result = lookup_ip_api(ip_address)
        if ip_api_result:
            results["ip-api"] = ip_api_result
    
    # IPinfo.io lookup (with optional API key)
    if provider in ["ipinfo", "all"]:
        ipinfo_result = lookup_ipinfo(ip_address)
        if ipinfo_result:
            results["ipinfo"] = ipinfo_result
    
    # Display the results
    display_ip_results(results, ip_address)
    
    # Save if requested
    if save:
        if format == "json":
            export_utils.save_to_json(results, "ip", ip_address)
        else:
            export_utils.save_to_csv(results, "ip", ip_address)


@ip_commands.command(name="whois")
@click.argument("target")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
def lookup_whois(target, save, format):
    """
    Perform a WHOIS lookup on an IP or domain.
    
    TARGET: The IP address or domain to look up.
    """
    console.print(f"[bold]WHOIS lookup for: [cyan]{target}[/cyan][/bold]")
    
    # Try to determine if the target is an IP or domain
    is_ip = is_valid_ip(target)
    
    with console.status(f"Performing WHOIS lookup for {target}..."):
        try:
            # Use the python-whois library for the lookup
            whois_info = whois.whois(target)
            
            # Also try to use the system whois command for more complete results
            try:
                proc = subprocess.run(
                    ["whois", target],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=get_setting("timeout")
                )
                
                if proc.returncode == 0:
                    raw_whois = proc.stdout
                else:
                    raw_whois = None
            except (subprocess.SubprocessError, FileNotFoundError):
                raw_whois = None
            
            # Combine the results
            results = {
                "python_whois": whois_info.copy() if whois_info else {},
                "raw_whois": raw_whois
            }
            
            # Display results
            display_whois_results(results, target, is_ip)
            
            # Save if requested
            if save:
                if format == "json":
                    # Convert non-serializable objects
                    for key, value in results["python_whois"].items():
                        if not isinstance(value, (str, int, float, bool, list, dict, type(None))):
                            results["python_whois"][key] = str(value)
                    
                    export_utils.save_to_json(results, "whois", target)
                else:
                    # Create a flattened version for CSV
                    flat_results = flatten_whois_for_csv(results["python_whois"])
                    export_utils.save_to_csv(flat_results, "whois", target)
            
            return results
                
        except Exception as e:
            console.print(f"[red]Error performing WHOIS lookup: {e}[/red]")
            return None


def lookup_ip_api(ip_address):
    """Look up IP information using IP-API.com (free, no API key required)."""
    with console.status(f"Looking up {ip_address} with IP-API.com..."):
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
                timeout=get_setting("timeout")
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return data
                else:
                    console.print(f"[red]IP-API.com error: {data.get('message', 'Unknown error')}[/red]")
                    return None
            else:
                console.print(f"[red]Error with IP-API.com: HTTP {response.status_code}[/red]")
                return None
                
        except Exception as e:
            console.print(f"[red]Error with IP-API.com: {e}[/red]")
            return None


def lookup_ipinfo(ip_address):
    """Look up IP information using IPinfo.io (free tier with API key)."""
    api_key = get_api_key("ipinfo")
    
    headers = {
        "User-Agent": get_setting("user_agent")
    }
    
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    
    with console.status(f"Looking up {ip_address} with IPinfo.io..."):
        try:
            response = requests.get(
                f"https://ipinfo.io/{ip_address}/json",
                headers=headers,
                timeout=get_setting("timeout")
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                console.print(f"[red]Error with IPinfo.io: HTTP {response.status_code}[/red]")
                return None
                
        except Exception as e:
            console.print(f"[red]Error with IPinfo.io: {e}[/red]")
            return None


def is_valid_ip(ip):
    """Check if the string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def display_ip_results(results, ip_address):
    """Display IP lookup results."""
    if not results:
        console.print(f"[yellow]No results found for IP [bold]{ip_address}[/bold][/yellow]")
        return
    
    # Determine which result to display
    ip_api_result = results.get("ip-api")
    ipinfo_result = results.get("ipinfo")
    
    # Create a panel for the main IP info
    ip_info = []
    
    if ip_api_result:
        ip_info.extend([
            "📍 [bold cyan]Location:[/bold cyan]",
            f"  [green]City:[/green] {ip_api_result.get('city', 'N/A')}, {ip_api_result.get('regionName', 'N/A')}, {ip_api_result.get('country', 'N/A')}",
            f"  [green]Coordinates:[/green] {ip_api_result.get('lat', 'N/A')}, {ip_api_result.get('lon', 'N/A')}",
            f"  [green]Timezone:[/green] {ip_api_result.get('timezone', 'N/A')}",
            "",
            "🏢 [bold cyan]Network:[/bold cyan]",
            f"  [green]ISP:[/green] {ip_api_result.get('isp', 'N/A')}",
            f"  [green]Organization:[/green] {ip_api_result.get('org', 'N/A')}",
            f"  [green]AS:[/green] {ip_api_result.get('as', 'N/A')}"
        ])
        
        # Add threat information if available
        if ip_api_result.get('proxy') or ip_api_result.get('hosting'):
            ip_info.extend([
                "",
                "⚠️ [bold red]Threat Info:[/bold red]",
                f"  [green]Proxy/VPN:[/green] {'Yes' if ip_api_result.get('proxy') else 'No'}",
                f"  [green]Hosting/Datacenter:[/green] {'Yes' if ip_api_result.get('hosting') else 'No'}",
                f"  [green]Mobile Network:[/green] {'Yes' if ip_api_result.get('mobile') else 'No'}"
            ])
    
    elif ipinfo_result:
        # If we only have IPinfo results
        location = f"{ipinfo_result.get('city', 'N/A')}, {ipinfo_result.get('region', 'N/A')}, {ipinfo_result.get('country', 'N/A')}"
        
        # Get coordinates if available
        coordinates = "N/A"
        if "loc" in ipinfo_result:
            coordinates = ipinfo_result["loc"]
        
        ip_info.extend([
            "📍 [bold cyan]Location:[/bold cyan]",
            f"  [green]City:[/green] {location}",
            f"  [green]Coordinates:[/green] {coordinates}",
            f"  [green]Timezone:[/green] {ipinfo_result.get('timezone', 'N/A')}",
            "",
            "🏢 [bold cyan]Network:[/bold cyan]",
            f"  [green]Organization:[/green] {ipinfo_result.get('org', 'N/A')}",
            f"  [green]Hostname:[/green] {ipinfo_result.get('hostname', 'N/A')}"
        ])
    
    # Create and display the panel
    ip_panel = Panel(
        "\n".join(ip_info),
        title=f"IP Information: [bold]{ip_address}[/bold]",
        border_style="blue"
    )
    
    console.print(ip_panel)


def display_whois_results(results, target, is_ip):
    """Display WHOIS lookup results."""
    python_whois = results.get("python_whois", {})
    raw_whois = results.get("raw_whois")
    
    if not python_whois and not raw_whois:
        console.print(f"[yellow]No WHOIS information found for [bold]{target}[/bold][/yellow]")
        return
    
    # Create a table for structured WHOIS information
    table = Table(title=f"WHOIS Information for [bold cyan]{target}[/bold cyan]")
    
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    
    # Add the most important fields first
    important_fields = []
    
    if is_ip:
        important_fields = [
            "asn", "asn_cidr", "asn_country_code", "asn_date", "asn_registry",
            "cidr", "country", "netrange", "organization", "updated"
        ]
    else:
        important_fields = [
            "domain_name", "registrar", "whois_server", "updated_date", "creation_date",
            "expiration_date", "name_servers", "status", "emails", "registrant",
            "registrant_country", "admin", "admin_country"
        ]
    
    # Add important fields
    for field in important_fields:
        if field in python_whois:
            value = python_whois[field]
            
            # Format lists
            if isinstance(value, list):
                if all(isinstance(item, (str, int, float)) for item in value):
                    value = "\n".join(str(item) for item in value)
                else:
                    value = json.dumps(value, indent=2, default=str)
            
            # Format dates
            elif hasattr(value, "strftime"):
                value = value.strftime("%Y-%m-%d %H:%M:%S")
            
            table.add_row(field.replace("_", " ").title(), str(value))
    
    # Add any remaining fields
    for field, value in python_whois.items():
        if field.lower() not in [f.lower() for f in important_fields]:
            # Format the value
            if isinstance(value, list):
                if all(isinstance(item, (str, int, float)) for item in value):
                    value = "\n".join(str(item) for item in value)
                else:
                    value = json.dumps(value, indent=2, default=str)
            elif hasattr(value, "strftime"):
                value = value.strftime("%Y-%m-%d %H:%M:%S")
            
            table.add_row(field.replace("_", " ").title(), str(value))
    
    console.print(table)
    
    # Display raw WHOIS if available
    if raw_whois:
        console.print(Panel(
            raw_whois[:1000] + ("..." if len(raw_whois) > 1000 else ""),
            title="Raw WHOIS Output (First 1000 chars)",
            border_style="blue"
        ))


def flatten_whois_for_csv(whois_data):
    """Flatten WHOIS data for CSV export."""
    flat_data = {}
    
    for key, value in whois_data.items():
        if isinstance(value, list):
            # For lists, join with commas
            if all(isinstance(item, (str, int, float)) for item in value):
                flat_data[key] = ", ".join(str(item) for item in value)
            else:
                flat_data[key] = json.dumps(value, default=str)
        elif hasattr(value, "strftime"):
            # Format dates
            flat_data[key] = value.strftime("%Y-%m-%d %H:%M:%S")
        else:
            flat_data[key] = value
    
    return flat_data 