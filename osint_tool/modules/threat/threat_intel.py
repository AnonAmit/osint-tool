"""
Threat Intelligence module for OSINT CLI Tool.
Includes VirusTotal and Shodan lookups.
"""

import re
import json
import hashlib
import socket
import ipaddress
from urllib.parse import urlparse

import click
import requests
import shodan
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from osint_tool.config import get_api_key, get_setting
from osint_tool.modules.utils import export_utils

console = Console()

# Define the Click command group
@click.group(name="threat")
def threat_commands():
    """Commands for threat intelligence lookups."""
    pass


@threat_commands.command(name="virustotal")
@click.argument("target")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
@click.option("--type", "-t", type=click.Choice(["auto", "url", "domain", "ip", "file", "hash"]), default="auto", 
              help="Type of target to check")
def check_virustotal(target, save, format, type):
    """
    Check a target against VirusTotal.
    
    TARGET: URL, domain, IP, file path, or file hash to check.
    """
    # Get API key
    api_key = get_api_key("virustotal")
    
    if not api_key:
        console.print("[red]VirusTotal API key not found![/red]")
        console.print("[yellow]You can get a free API key from https://www.virustotal.com/gui/[/yellow]")
        console.print("[yellow]Set it in your .env file as OSINT_VIRUSTOTAL_API_KEY=your_key[/yellow]")
        return
    
    # Determine target type if auto
    if type == "auto":
        type = detect_target_type(target)
        console.print(f"[blue]Detected target type: [bold]{type}[/bold][/blue]")
    
    # Check the target
    results = check_target_virustotal(target, type, api_key)
    
    # Display results
    if results:
        display_virustotal_results(results, target, type)
        
        # Save if requested
        if save:
            if format == "json":
                export_utils.save_to_json(results, "virustotal", target.replace(":", "_"))
            else:
                # Flatten results for CSV
                flat_results = flatten_virustotal_results(results, type)
                export_utils.save_to_csv(flat_results, "virustotal", target.replace(":", "_"))
    else:
        console.print(f"[yellow]No results found for {target}[/yellow]")


@threat_commands.command(name="shodan")
@click.argument("target")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
@click.option("--type", "-t", type=click.Choice(["auto", "ip", "domain", "search"]), default="auto", 
              help="Type of target to check")
def check_shodan(target, save, format, type):
    """
    Look up information on Shodan.
    
    TARGET: IP address, domain, or search query.
    """
    # Get API key
    api_key = get_api_key("shodan")
    
    if not api_key:
        console.print("[red]Shodan API key not found![/red]")
        console.print("[yellow]You can get a free API key from https://account.shodan.io/register[/yellow]")
        console.print("[yellow]Set it in your .env file as OSINT_SHODAN_API_KEY=your_key[/yellow]")
        return
    
    # Determine target type if auto
    if type == "auto":
        if is_valid_ip(target):
            type = "ip"
        elif is_valid_domain(target):
            type = "domain"
        else:
            type = "search"
        
        console.print(f"[blue]Detected target type: [bold]{type}[/bold][/blue]")
    
    # Check the target
    results = check_target_shodan(target, type, api_key)
    
    # Display results
    if results:
        display_shodan_results(results, target, type)
        
        # Save if requested
        if save:
            if format == "json":
                export_utils.save_to_json(results, "shodan", target.replace(":", "_"))
            else:
                # Convert for CSV
                if type == "search":
                    # For search results, create a list of matches
                    flat_results = []
                    for match in results.get("matches", []):
                        flat_result = {
                            "ip": match.get("ip_str", ""),
                            "port": match.get("port", ""),
                            "hostnames": ", ".join(match.get("hostnames", [])),
                            "org": match.get("org", ""),
                            "country": match.get("location", {}).get("country_name", ""),
                            "timestamp": match.get("timestamp", "")
                        }
                        flat_results.append(flat_result)
                    
                    export_utils.save_to_csv(flat_results, "shodan_search", target)
                else:
                    # For IP/domain results, flatten the dictionary
                    flat_results = {}
                    for key, value in results.items():
                        if isinstance(value, (str, int, float, bool)):
                            flat_results[key] = value
                        elif isinstance(value, list) and all(isinstance(x, (str, int, float, bool)) for x in value):
                            flat_results[key] = ", ".join(str(x) for x in value)
                    
                    export_utils.save_to_csv(flat_results, "shodan", target)
    else:
        console.print(f"[yellow]No Shodan results found for {target}[/yellow]")


def detect_target_type(target):
    """Detect the type of a target for VirusTotal."""
    # Check if it's a URL
    if target.startswith(("http://", "https://", "ftp://")):
        return "url"
    
    # Check if it's an IP address
    if is_valid_ip(target):
        return "ip"
    
    # Check if it's a domain
    if is_valid_domain(target):
        return "domain"
    
    # Check if it's a file path
    if target.startswith(("/", "./", "../", "c:", "C:", "D:", "d:", "\\", ".\\", "..\\")) or "\\" in target:
        return "file"
    
    # Check if it's a hash (MD5, SHA-1, SHA-256)
    if re.match(r'^[a-fA-F0-9]{32}$', target) or re.match(r'^[a-fA-F0-9]{40}$', target) or re.match(r'^[a-fA-F0-9]{64}$', target):
        return "hash"
    
    # Default to URL since most things can be checked as URLs
    return "url"


def is_valid_ip(ip):
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_domain(domain):
    """Check if a string is a valid domain name."""
    # Basic domain validation
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(domain))


def calculate_file_hash(file_path):
    """Calculate MD5, SHA-1, and SHA-256 hashes of a file."""
    try:
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            # Read the file in chunks to avoid loading large files into memory
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return {
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }
    except Exception as e:
        console.print(f"[red]Error calculating file hash: {e}[/red]")
        return None


def check_target_virustotal(target, type, api_key):
    """Check a target against VirusTotal API."""
    base_url = "https://www.virustotal.com/api/v3"
    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/json"
    }
    
    with console.status(f"Checking {type} with VirusTotal..."):
        try:
            # Handle different target types
            if type == "url":
                # For URLs, we need to get the URL ID first by submitting it
                url_id = get_virustotal_url_id(target, api_key)
                if url_id:
                    response = requests.get(
                        f"{base_url}/urls/{url_id}",
                        headers=headers,
                        timeout=get_setting("timeout")
                    )
                else:
                    return None
            
            elif type == "domain":
                response = requests.get(
                    f"{base_url}/domains/{target}",
                    headers=headers,
                    timeout=get_setting("timeout")
                )
            
            elif type == "ip":
                response = requests.get(
                    f"{base_url}/ip_addresses/{target}",
                    headers=headers,
                    timeout=get_setting("timeout")
                )
            
            elif type == "file":
                # For files, we calculate the hash and then check the hash
                hashes = calculate_file_hash(target)
                if not hashes:
                    return None
                
                response = requests.get(
                    f"{base_url}/files/{hashes['sha256']}",
                    headers=headers,
                    timeout=get_setting("timeout")
                )
                
                # If the file is not found, display the calculated hashes anyway
                if response.status_code == 404:
                    return {"calculated_hashes": hashes, "found": False}
            
            elif type == "hash":
                response = requests.get(
                    f"{base_url}/files/{target}",
                    headers=headers,
                    timeout=get_setting("timeout")
                )
            
            else:
                console.print(f"[red]Unknown target type: {type}[/red]")
                return None
            
            # Process the response
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                console.print(f"[yellow]Target not found in VirusTotal: {target}[/yellow]")
                return None
            else:
                console.print(f"[red]Error from VirusTotal API: {response.status_code} - {response.text}[/red]")
                return None
                
        except Exception as e:
            console.print(f"[red]Error checking VirusTotal: {e}[/red]")
            return None


def get_virustotal_url_id(url, api_key):
    """Get VirusTotal URL ID by submitting the URL."""
    base_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        # Submit the URL
        data = {"url": url}
        response = requests.post(
            base_url,
            headers=headers,
            data=data,
            timeout=get_setting("timeout")
        )
        
        if response.status_code == 200:
            result = response.json()
            # The URL ID is in the "id" field
            return result.get("data", {}).get("id")
        else:
            console.print(f"[red]Error submitting URL to VirusTotal: {response.status_code} - {response.text}[/red]")
            return None
            
    except Exception as e:
        console.print(f"[red]Error submitting URL to VirusTotal: {e}[/red]")
        return None


def check_target_shodan(target, type, api_key):
    """Look up information on Shodan."""
    try:
        # Initialize Shodan API
        api = shodan.Shodan(api_key)
        
        with console.status(f"Querying Shodan for {target}..."):
            if type == "ip":
                return api.host(target)
            
            elif type == "domain":
                # Resolve the domain to an IP first
                try:
                    ip = socket.gethostbyname(target)
                    result = api.host(ip)
                    result["domain"] = target
                    result["resolved_ip"] = ip
                    return result
                except socket.gaierror:
                    console.print(f"[yellow]Could not resolve domain {target} to an IP address[/yellow]")
                    return None
            
            elif type == "search":
                return api.search(target)
            
            else:
                console.print(f"[red]Unknown target type for Shodan: {type}[/red]")
                return None
                
    except shodan.APIError as e:
        if "No information available" in str(e):
            console.print(f"[yellow]No information available on Shodan for {target}[/yellow]")
        else:
            console.print(f"[red]Shodan API Error: {e}[/red]")
        return None
        
    except Exception as e:
        console.print(f"[red]Error querying Shodan: {e}[/red]")
        return None


def display_virustotal_results(results, target, type):
    """Display VirusTotal results in a formatted way."""
    # Handle file hashes separately
    if "calculated_hashes" in results:
        hashes = results["calculated_hashes"]
        
        table = Table(title=f"File Hashes for [bold cyan]{target}[/bold cyan]")
        
        table.add_column("Hash Type", style="cyan")
        table.add_column("Value", style="green")
        
        for hash_type, hash_value in hashes.items():
            table.add_row(hash_type.upper(), hash_value)
        
        console.print(table)
        
        if not results.get("found", True):
            console.print("[yellow]This file has not been scanned on VirusTotal.[/yellow]")
            console.print("[yellow]You can submit it manually at https://www.virustotal.com/gui/[/yellow]")
        
        return
    
    # Extract data from the response
    data = results.get("data", {})
    attributes = data.get("attributes", {})
    
    # Display header panel with basic info
    header_info = []
    
    if type == "url":
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        total = sum(last_analysis_stats.values())
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        
        header_info.extend([
            f"[cyan]URL:[/cyan] {attributes.get('url', target)}",
            f"[cyan]Last Analysis:[/cyan] {attributes.get('last_analysis_date', 'Unknown')}",
            f"[cyan]Detection:[/cyan] {malicious + suspicious}/{total} engines flagged this URL"
        ])
    
    elif type == "domain":
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        total = sum(last_analysis_stats.values())
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        
        header_info.extend([
            f"[cyan]Domain:[/cyan] {target}",
            f"[cyan]Creation Date:[/cyan] {attributes.get('creation_date', 'Unknown')}",
            f"[cyan]Last Update:[/cyan] {attributes.get('last_update_date', 'Unknown')}",
            f"[cyan]Detection:[/cyan] {malicious + suspicious}/{total} engines flagged this domain"
        ])
    
    elif type == "ip":
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        total = sum(last_analysis_stats.values())
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        
        header_info.extend([
            f"[cyan]IP Address:[/cyan] {target}",
            f"[cyan]ASN:[/cyan] {attributes.get('asn', 'Unknown')}",
            f"[cyan]Country:[/cyan] {attributes.get('country', 'Unknown')}",
            f"[cyan]Detection:[/cyan] {malicious + suspicious}/{total} engines flagged this IP"
        ])
    
    elif type in ["hash", "file"]:
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        total = sum(last_analysis_stats.values())
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        
        header_info.extend([
            f"[cyan]File Type:[/cyan] {attributes.get('type_description', 'Unknown')}",
            f"[cyan]Size:[/cyan] {attributes.get('size', 'Unknown')} bytes",
            f"[cyan]MD5:[/cyan] {attributes.get('md5', 'Unknown')}",
            f"[cyan]SHA-1:[/cyan] {attributes.get('sha1', 'Unknown')}",
            f"[cyan]SHA-256:[/cyan] {attributes.get('sha256', 'Unknown')}",
            f"[cyan]Detection:[/cyan] {malicious + suspicious}/{total} engines flagged this file"
        ])
    
    header_panel = Panel(
        "\n".join(header_info),
        title=f"VirusTotal Results for [bold]{target}[/bold]",
        border_style="blue"
    )
    
    console.print(header_panel)
    
    # Display detection table if available
    if "last_analysis_results" in attributes:
        last_analysis = attributes["last_analysis_results"]
        
        # Create a table for the scanner results
        table = Table(title="Antivirus Detection Results")
        
        table.add_column("Scanner", style="cyan")
        table.add_column("Category", style="green")
        table.add_column("Result", style="yellow")
        
        # Add rows for malicious or suspicious results
        malicious_results = []
        
        for scanner, result in last_analysis.items():
            category = result.get("category", "")
            if category in ["malicious", "suspicious"]:
                malicious_results.append((scanner, category, result.get("result", "")))
        
        # Sort by scanner name
        for scanner, category, result_text in sorted(malicious_results):
            table.add_row(scanner, category, result_text if result_text else "Unknown")
        
        if malicious_results:
            console.print(table)
        else:
            console.print("[green]No engines flagged this target as malicious or suspicious.[/green]")
    
    # Add link to full report
    if type == "url":
        url_id = data.get("id", "")
        console.print(f"[cyan]Full report:[/cyan] https://www.virustotal.com/gui/url/{url_id}")
    elif type == "domain":
        console.print(f"[cyan]Full report:[/cyan] https://www.virustotal.com/gui/domain/{target}")
    elif type == "ip":
        console.print(f"[cyan]Full report:[/cyan] https://www.virustotal.com/gui/ip-address/{target}")
    elif type in ["hash", "file"]:
        file_id = data.get("id", "")
        console.print(f"[cyan]Full report:[/cyan] https://www.virustotal.com/gui/file/{file_id}")


def flatten_virustotal_results(results, type):
    """Flatten VirusTotal results for CSV export."""
    # Special case for file hashes
    if "calculated_hashes" in results:
        return results["calculated_hashes"]
    
    data = results.get("data", {})
    attributes = data.get("attributes", {})
    
    flat_data = {}
    
    # Flatten basic attributes
    for key, value in attributes.items():
        if isinstance(value, (str, int, float, bool)):
            flat_data[key] = value
        elif key == "last_analysis_stats":
            for stat_key, stat_value in value.items():
                flat_data[f"stat_{stat_key}"] = stat_value
    
    return flat_data


def display_shodan_results(results, target, type):
    """Display Shodan results in a formatted way."""
    if type == "search":
        # Display search results
        total = results.get("total", 0)
        matches = results.get("matches", [])
        
        console.print(f"[green]Found {total} matches for query: [bold]{target}[/bold][/green]")
        
        table = Table(title=f"Shodan Search Results for [bold cyan]{target}[/bold cyan]")
        
        table.add_column("IP", style="cyan")
        table.add_column("Port", style="green")
        table.add_column("Hostnames", style="yellow")
        table.add_column("Organization", style="blue")
        table.add_column("Country", style="magenta")
        
        for match in matches[:20]:  # Limit to 20 results to avoid overwhelming output
            ip = match.get("ip_str", "Unknown")
            port = str(match.get("port", ""))
            hostnames = ", ".join(match.get("hostnames", []))
            org = match.get("org", "Unknown")
            country = match.get("location", {}).get("country_name", "Unknown")
            
            table.add_row(ip, port, hostnames, org, country)
        
        console.print(table)
        
        if len(matches) > 20:
            console.print(f"[yellow]Showing 20 of {len(matches)} results.[/yellow]")
    
    else:
        # Display host information
        domain = results.get("domain", target) if "domain" in results else target
        hostnames = ", ".join(results.get("hostnames", []))
        org = results.get("org", "Unknown")
        country = results.get("country_name", "Unknown")
        city = results.get("city", "Unknown")
        isp = results.get("isp", "Unknown")
        last_update = results.get("last_update", "Unknown")
        ports = results.get("ports", [])
        
        # Create info panel
        info = [
            f"[cyan]IP:[/cyan] {results.get('ip_str', 'Unknown')}",
            f"[cyan]Hostnames:[/cyan] {hostnames}",
            f"[cyan]Organization:[/cyan] {org}",
            f"[cyan]ISP:[/cyan] {isp}",
            f"[cyan]Location:[/cyan] {city}, {country}",
            f"[cyan]Last Update:[/cyan] {last_update}",
            f"[cyan]Open Ports:[/cyan] {', '.join(map(str, sorted(ports)))}"
        ]
        
        info_panel = Panel(
            "\n".join(info),
            title=f"Shodan Information for [bold]{domain}[/bold]",
            border_style="blue"
        )
        
        console.print(info_panel)
        
        # Create a table for services
        if "data" in results:
            services = results["data"]
            
            table = Table(title="Open Services")
            
            table.add_column("Port", style="cyan")
            table.add_column("Protocol", style="green")
            table.add_column("Service", style="yellow")
            table.add_column("Banner", style="blue")
            
            for service in services:
                port = str(service.get("port", ""))
                transport = service.get("transport", "")
                product = service.get("product", "")
                banner = service.get("data", "").strip()
                
                # Truncate banner if too long
                if len(banner) > 100:
                    banner = banner[:97] + "..."
                
                service_name = product if product else service.get("_shodan", {}).get("module", "")
                
                table.add_row(port, transport, service_name, banner)
            
            console.print(table)
        
        # Add link to full report
        ip = results.get("ip_str", "")
        if ip:
            console.print(f"[cyan]Full report:[/cyan] https://www.shodan.io/host/{ip}") 