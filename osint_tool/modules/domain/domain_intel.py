"""
Domain and Website Intelligence module for OSINT CLI Tool.
Includes DNS, subdomains, and port scanning capabilities.
"""

import re
import json
import socket
import subprocess
from urllib.parse import urlparse

import click
import requests
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from osint_tool.config import get_setting
from osint_tool.modules.utils import export_utils

console = Console()

# Define the Click command group
@click.group(name="domain")
def domain_commands():
    """Commands for domain and website intelligence."""
    pass


@domain_commands.command(name="dns")
@click.argument("domain")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
@click.option("--all", "-a", is_flag=True, help="Check all DNS record types")
def check_dns(domain, save, format, all):
    """
    Check DNS records for a domain.
    
    DOMAIN: The domain to check.
    """
    # Clean the domain
    domain = clean_domain(domain)
    
    console.print(f"[bold]Checking DNS records for: [cyan]{domain}[/cyan][/bold]")
    
    # Define record types to check
    if all:
        record_types = [
            "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA", "PTR"
        ]
    else:
        record_types = [
            "A", "AAAA", "CNAME", "MX", "NS", "TXT"
        ]
    
    results = {}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}[/bold blue]"),
        console=console
    ) as progress:
        task = progress.add_task(f"Checking DNS records...", total=len(record_types))
        
        # Check each record type
        for record_type in record_types:
            try:
                dns_results = query_dns(domain, record_type)
                if dns_results:
                    results[record_type] = dns_results
            except Exception as e:
                console.print(f"[yellow]Error checking {record_type} records: {e}[/yellow]")
            
            progress.update(task, advance=1)
    
    # Display results
    display_dns_results(results, domain)
    
    # Save if requested
    if save:
        if format == "json":
            export_utils.save_to_json(results, "dns", domain)
        else:
            export_utils.save_to_csv(results, "dns", domain)


@domain_commands.command(name="subdomains")
@click.argument("domain")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
@click.option("--method", "-m", type=click.Choice(["sublist3r", "dnsdumpster", "both"]), default="both", 
              help="Method for subdomain discovery")
def find_subdomains(domain, save, format, method):
    """
    Find subdomains for a domain.
    
    DOMAIN: The main domain to check for subdomains.
    """
    # Clean the domain
    domain = clean_domain(domain)
    
    console.print(f"[bold]Searching for subdomains of: [cyan]{domain}[/cyan][/bold]")
    
    results = {"subdomains": []}
    
    # Try using Sublist3r if available and requested
    if method in ["sublist3r", "both"]:
        sublist3r_results = run_sublist3r(domain)
        if sublist3r_results:
            results["subdomains"].extend(sublist3r_results)
    
    # Use DNSDumpster API as fallback or if requested
    if method in ["dnsdumpster", "both"] and (method == "dnsdumpster" or not results["subdomains"]):
        dnsdumpster_results = check_dnsdumpster(domain)
        if dnsdumpster_results:
            # Avoid duplicates
            existing_subdomains = set(results["subdomains"])
            for subdomain in dnsdumpster_results:
                if subdomain not in existing_subdomains:
                    results["subdomains"].append(subdomain)
    
    # Sort and deduplicate results
    results["subdomains"] = sorted(list(set(results["subdomains"])))
    
    # Try to resolve each subdomain to get its IP
    if results["subdomains"]:
        resolved_subdomains = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}[/bold blue]"),
            console=console
        ) as progress:
            task = progress.add_task(f"Resolving subdomains...", total=len(results["subdomains"]))
            
            for subdomain in results["subdomains"]:
                ip = resolve_hostname(subdomain)
                resolved_subdomains.append({
                    "subdomain": subdomain,
                    "ip": ip if ip else "Could not resolve"
                })
                progress.update(task, advance=1)
        
        results["resolved"] = resolved_subdomains
    
    # Display results
    display_subdomains_results(results, domain)
    
    # Save if requested
    if save:
        if format == "json":
            export_utils.save_to_json(results, "subdomains", domain)
        else:
            # Flattened version for CSV
            export_utils.save_to_csv(results["resolved"] if "resolved" in results else [], "subdomains", domain)


@domain_commands.command(name="portscan")
@click.argument("target")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
@click.option("--ports", "-p", default="common", help="Ports to scan: 'common', 'top100', 'top1000', or comma-separated list")
def scan_ports(target, save, format, ports):
    """
    Scan ports on a target using nmap if available.
    
    TARGET: IP address or domain to scan.
    """
    # Clean the target
    target = clean_domain(target)
    
    console.print(f"[bold]Scanning ports on: [cyan]{target}[/cyan][/bold]")
    
    # Check if nmap is installed
    nmap_available = is_nmap_installed()
    
    if nmap_available:
        # Convert port specification to nmap format
        port_arg = convert_ports_to_nmap_format(ports)
        
        # Run nmap
        nmap_results = run_nmap(target, port_arg)
        
        # Display results
        display_portscan_results(nmap_results, target)
        
        # Save if requested
        if save:
            if format == "json":
                export_utils.save_to_json(nmap_results, "portscan", target)
            else:
                # Create a flattened version for CSV
                flat_results = []
                for port, details in nmap_results.get("ports", {}).items():
                    flat_details = {"port": port}
                    flat_details.update(details)
                    flat_results.append(flat_details)
                
                export_utils.save_to_csv(flat_results, "portscan", target)
    else:
        console.print("[red]Nmap is not installed or not in PATH. Cannot perform port scan.[/red]")
        console.print("[yellow]Try installing nmap with your package manager:[/yellow]")
        console.print("- Linux: sudo apt install nmap")
        console.print("- macOS: brew install nmap")
        console.print("- Windows: Download from https://nmap.org/download.html")


def clean_domain(domain):
    """Clean a domain name by removing protocol and path components."""
    # Remove protocol if present
    if "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.netloc
    
    # Remove path, query, etc.
    domain = domain.split("/")[0].split("?")[0].split("#")[0].strip()
    
    return domain


def query_dns(domain, record_type):
    """Query DNS records of a specific type for a domain."""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        results = []
        
        for rdata in answers:
            if record_type == "MX":
                results.append({
                    "preference": rdata.preference,
                    "exchange": rdata.exchange.to_text()
                })
            elif record_type == "SOA":
                results.append({
                    "mname": rdata.mname.to_text(),
                    "rname": rdata.rname.to_text(),
                    "serial": rdata.serial,
                    "refresh": rdata.refresh,
                    "retry": rdata.retry,
                    "expire": rdata.expire,
                    "minimum": rdata.minimum
                })
            elif record_type == "SRV":
                results.append({
                    "priority": rdata.priority,
                    "weight": rdata.weight,
                    "port": rdata.port,
                    "target": rdata.target.to_text()
                })
            else:
                results.append(rdata.to_text())
        
        return results
    
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        # Other DNS errors
        raise Exception(f"DNS error: {str(e)}")


def display_dns_results(results, domain):
    """Display DNS lookup results in a table."""
    if not results:
        console.print(f"[yellow]No DNS records found for [bold]{domain}[/bold][/yellow]")
        return
    
    for record_type, records in results.items():
        table = Table(title=f"{record_type} Records for [bold cyan]{domain}[/bold cyan]")
        
        if record_type == "MX":
            table.add_column("Preference", style="cyan")
            table.add_column("Exchange", style="green")
            
            for record in records:
                table.add_row(
                    str(record.get("preference", "")),
                    record.get("exchange", "")
                )
        
        elif record_type == "SOA":
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")
            
            for record in records:
                for field, value in record.items():
                    table.add_row(field.title(), str(value))
        
        elif record_type == "SRV":
            table.add_column("Priority", style="cyan")
            table.add_column("Weight", style="green")
            table.add_column("Port", style="green")
            table.add_column("Target", style="green")
            
            for record in records:
                table.add_row(
                    str(record.get("priority", "")),
                    str(record.get("weight", "")),
                    str(record.get("port", "")),
                    record.get("target", "")
                )
        
        else:
            table.add_column("Value", style="green")
            
            for record in records:
                table.add_row(record)
        
        console.print(table)


def run_sublist3r(domain):
    """Run Sublist3r to find subdomains if available."""
    try:
        # Check if Sublist3r is installed
        sublist3r_installed = False
        sublist3r_module = None
        
        try:
            # Try importing Sublist3r as a module first
            import sublist3r
            sublist3r_installed = True
            sublist3r_module = sublist3r
        except ImportError:
            # Try alternative import paths
            try:
                import Sublist3r as sublist3r
                sublist3r_installed = True
                sublist3r_module = sublist3r
            except ImportError:
                pass
        
        if not sublist3r_installed:
            # Try running it as a command
            try:
                # Check for 'sublist3r' command
                result = subprocess.run(
                    ["sublist3r", "--help"], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    timeout=5
                )
                sublist3r_installed = (result.returncode == 0)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                # Check for 'Sublist3r.py' command
                try:
                    result = subprocess.run(
                        ["python", "-m", "Sublist3r", "--help"], 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        timeout=5
                    )
                    sublist3r_installed = (result.returncode == 0)
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass
        
        if not sublist3r_installed:
            console.print("[yellow]Sublist3r not found, falling back to DNSDumpster...[/yellow]")
            return None
        
        with console.status(f"Running Sublist3r for {domain}..."):
            if sublist3r_module:
                # Use it as a module
                try:
                    subdomains = sublist3r_module.main(
                        domain, 
                        40, 
                        savefile=None, 
                        ports=None, 
                        silent=True, 
                        verbose=False, 
                        enable_bruteforce=False, 
                        engines=None
                    )
                    if isinstance(subdomains, list):
                        return subdomains
                    elif hasattr(subdomains, '__iter__'):
                        return list(subdomains)
                    else:
                        console.print("[yellow]Unexpected result from Sublist3r module, trying command line...[/yellow]")
                except Exception as e:
                    console.print(f"[yellow]Error using Sublist3r module: {e}, trying command line...[/yellow]")
            
            # Fallback to command line
            try:
                # Create a temporary file for output
                import tempfile
                with tempfile.NamedTemporaryFile(delete=False, mode='w+t', suffix='.txt') as temp_file:
                    output_file = temp_file.name
                
                try:
                    # First try with 'sublist3r' command
                    process = subprocess.run(
                        ["sublist3r", "-d", domain, "-o", output_file, "-v"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=get_setting("timeout")
                    )
                except FileNotFoundError:
                    # Try with 'python -m Sublist3r'
                    process = subprocess.run(
                        ["python", "-m", "Sublist3r", "-d", domain, "-o", output_file, "-v"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=get_setting("timeout")
                    )
                
                # Parse output from command
                subdomains = []
                
                # Try to read from the output file
                try:
                    with open(output_file, 'r') as f:
                        subdomains = [line.strip() for line in f if line.strip()]
                except Exception as e:
                    console.print(f"[yellow]Error reading output file: {e}, parsing stdout instead[/yellow]")
                    # If file reading fails, parse from stdout
                    output = process.stdout
                    for line in output.splitlines():
                        # Look for domain names in the output
                        if domain in line:
                            parts = line.split()
                            for part in parts:
                                if domain in part and "." in part and not part.startswith('['):
                                    subdomain = part.strip()
                                    if subdomain and subdomain.endswith(domain) and subdomain != domain:
                                        subdomains.append(subdomain)
                
                # Try to clean up the temp file
                try:
                    import os
                    os.unlink(output_file)
                except:
                    pass
                
                # If we found subdomains, return them
                if subdomains:
                    return subdomains
                
                # Last resort: try to extract domains from stdout with regex
                if not subdomains:
                    output = process.stdout + process.stderr
                    subdomain_pattern = re.compile(r'(?<![a-zA-Z0-9-])([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(domain) + r'(?![a-zA-Z0-9-])')
                    
                    for match in subdomain_pattern.finditer(output):
                        subdomain = match.group(0)
                        if subdomain != domain and subdomain not in subdomains:
                            subdomains.append(subdomain)
                
                return subdomains
                
            except Exception as e:
                console.print(f"[red]Error running Sublist3r command: {e}[/red]")
                return None
    
    except Exception as e:
        console.print(f"[red]Error running Sublist3r: {e}[/red]")
        return None


def check_dnsdumpster(domain):
    """Use DNSDumpster to find subdomains."""
    with console.status(f"Checking DNSDumpster for {domain}..."):
        try:
            # First get a CSRF token from the homepage
            session = requests.Session()
            
            # Get the CSRF token from the homepage
            homepage = session.get(
                "https://dnsdumpster.com/",
                timeout=get_setting("timeout"),
                headers={"User-Agent": get_setting("user_agent")}
            )
            
            # Extract the CSRF token - updated extraction method
            csrf_token = None
            
            # First try cookies
            if session.cookies.get("csrftoken"):
                csrf_token = session.cookies.get("csrftoken")
            
            # Then try HTML extraction with a more robust pattern
            if not csrf_token:
                csrf_matches = re.findall(r'name=["\']csrfmiddlewaretoken["\'] value=["\'](.*?)["\']', homepage.text)
                if csrf_matches:
                    csrf_token = csrf_matches[0]
            
            if not csrf_token:
                # As a last resort, try to find any input with csrf in the name
                csrf_matches = re.findall(r'input.*?csrf.*?value=["\'](.*?)["\']', homepage.text, re.IGNORECASE)
                if csrf_matches:
                    csrf_token = csrf_matches[0]
            
            if not csrf_token:
                console.print("[red]Could not get CSRF token for DNSDumpster. Using alternative method...[/red]")
                # Try alternative method - direct scraping without form submission
                return scrape_dnsdumpster_without_csrf(domain, session)
            
            # Submit the form with the CSRF token
            headers = {
                "User-Agent": get_setting("user_agent"),
                "Referer": "https://dnsdumpster.com/",
                "Origin": "https://dnsdumpster.com",
                "X-CSRFToken": csrf_token
            }
            
            data = {
                "csrfmiddlewaretoken": csrf_token,
                "targetip": domain,
                "user": "free"
            }
            
            response = session.post(
                "https://dnsdumpster.com/",
                headers=headers,
                data=data,
                timeout=get_setting("timeout")
            )
            
            # Extract subdomains from the response
            return extract_subdomains_from_response(response.text, domain)
            
        except Exception as e:
            console.print(f"[red]Error with DNSDumpster: {e}[/red]")
            return None


def scrape_dnsdumpster_without_csrf(domain, session=None):
    """Alternative method to get subdomains from DNSDumpster without CSRF token."""
    try:
        if not session:
            session = requests.Session()
            
        # Use a direct GET request with the domain as a query parameter
        response = session.get(
            f"https://dnsdumpster.com/?q={domain}",
            headers={"User-Agent": get_setting("user_agent")},
            timeout=get_setting("timeout")
        )
        
        return extract_subdomains_from_response(response.text, domain)
        
    except Exception as e:
        console.print(f"[red]Error with alternative DNSDumpster method: {e}[/red]")
        return None


def extract_subdomains_from_response(html_content, domain):
    """Extract subdomains from DNSDumpster HTML response."""
    subdomains = []
    
    # Pattern to match subdomains more accurately
    # This looks for domain names in various contexts within the HTML
    subdomain_pattern = re.compile(r'(?<![a-zA-Z0-9-])([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(domain) + r'(?![a-zA-Z0-9-])')
    
    # Find all matches
    for match in subdomain_pattern.finditer(html_content):
        subdomain = match.group(0)
        # Skip if it's just the main domain
        if subdomain != domain and subdomain not in subdomains and not subdomain.startswith("."):
            subdomains.append(subdomain)
    
    # Also try to find subdomains in table cells specifically
    cell_pattern = re.compile(r'<td.*?>(.*?)</td>', re.DOTALL)
    for cell_match in cell_pattern.finditer(html_content):
        cell_content = cell_match.group(1)
        # Look for domain-like patterns in the cell
        for domain_match in subdomain_pattern.finditer(cell_content):
            subdomain = domain_match.group(0)
            if subdomain != domain and subdomain not in subdomains and not subdomain.startswith("."):
                subdomains.append(subdomain)
    
    return subdomains


def resolve_hostname(hostname):
    """Resolve a hostname to an IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def display_subdomains_results(results, domain):
    """Display subdomain search results in a table."""
    subdomains = results.get("subdomains", [])
    
    if not subdomains:
        console.print(f"[yellow]No subdomains found for {domain}[/yellow]")
        
        # Suggest alternative methods
        console.print("\n[bold]Try these alternatives:[/bold]")
        console.print("1. Install Sublist3r for better subdomain discovery:")
        console.print("   - pip install sublist3r")
        console.print("2. Use a different domain intelligence platform like SecurityTrails or VirusTotal")
        console.print("3. Try a different domain or check if the domain exists")
        return
    
    console.print(f"\n[bold green]Found {len(subdomains)} subdomains for {domain}:[/bold green]")
    
    # Create a table
    table = Table()
    table.add_column("Subdomain", style="cyan")
    
    if "resolved" in results and results["resolved"]:
        table.add_column("IP Address", style="green")
        
        for item in results["resolved"]:
            subdomain = item.get("subdomain", "")
            ip = item.get("ip", "Could not resolve")
            
            table.add_row(subdomain, ip)
    else:
        for subdomain in subdomains:
            table.add_row(subdomain)
    
    console.print(table)


def is_nmap_installed():
    """Check if nmap is installed."""
    try:
        result = subprocess.run(
            ["nmap", "--version"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def convert_ports_to_nmap_format(ports):
    """Convert port specification to nmap format."""
    if ports == "common":
        return "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    elif ports == "top100":
        return "1,3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464,465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053,1054,1056,1058,1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2002,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157,50000"
    elif ports == "top1000":
        return "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"
    else:
        # Assume it's a comma-separated list
        return ports


def run_nmap(target, port_arg):
    """Run nmap port scan on a target."""
    with console.status(f"Scanning ports on {target}..."):
        try:
            # Basic scan options
            cmd = [
                "nmap",
                "-p", port_arg,
                "-sV",  # Version detection
                "--open",  # Only show open ports
                target
            ]
            
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=get_setting("timeout") * 2  # Port scanning needs more time
            )
            
            if process.returncode != 0:
                console.print(f"[red]Error running nmap: {process.stderr}[/red]")
                return None
            
            # Parse nmap output
            output = process.stdout
            return parse_nmap_output(output, target)
            
        except subprocess.TimeoutExpired:
            console.print(f"[yellow]Nmap scan timed out. Try running with fewer ports or directly.[/yellow]")
            return {"error": "Timeout", "command": " ".join(cmd)}
        
        except Exception as e:
            console.print(f"[red]Error running nmap: {e}[/red]")
            return None


def parse_nmap_output(output, target):
    """Parse nmap output into a structured format."""
    results = {
        "target": target,
        "ports": {}
    }
    
    # Extract general information
    start_time_match = re.search(r'Starting Nmap ([0-9.]+) \( http://nmap.org \) at (.+)', output)
    if start_time_match:
        results["nmap_version"] = start_time_match.group(1)
        results["scan_time"] = start_time_match.group(2)
    
    # Extract ports
    port_section = False
    current_port = None
    
    for line in output.splitlines():
        # Check for port lines
        port_match = re.search(r'(\d+)\/(\w+)\s+(\w+)\s+(.+)', line)
        if port_match:
            port_section = True
            current_port = port_match.group(1)
            results["ports"][current_port] = {
                "protocol": port_match.group(2),
                "state": port_match.group(3),
                "service": port_match.group(4)
            }
        
        # Check for service details
        elif port_section and current_port and "|" in line:
            parts = line.strip().split("|")
            for part in parts:
                if ":" in part:
                    key, value = part.split(":", 1)
                    results["ports"][current_port][key.strip()] = value.strip()
    
    return results


def display_portscan_results(results, target):
    """Display port scan results in a table."""
    if not results or "error" in results:
        if results and "error" in results:
            console.print(f"[red]Error scanning ports: {results['error']}[/red]")
        else:
            console.print(f"[yellow]No open ports found on [bold]{target}[/bold][/yellow]")
        return
    
    ports = results.get("ports", {})
    
    if not ports:
        console.print(f"[yellow]No open ports found on [bold]{target}[/bold][/yellow]")
        return
    
    table = Table(title=f"Open Ports on [bold cyan]{target}[/bold cyan]")
    
    table.add_column("Port", style="cyan")
    table.add_column("Protocol", style="yellow")
    table.add_column("Service", style="green")
    table.add_column("Version", style="blue")
    
    for port, details in ports.items():
        version = ""
        if "product" in details:
            version = details["product"]
            if "version" in details:
                version += f" {details['version']}"
        
        table.add_row(
            port,
            details.get("protocol", ""),
            details.get("service", ""),
            version
        )
    
    console.print(table)
    console.print(f"[green]Found {len(ports)} open ports on {target}[/green]") 