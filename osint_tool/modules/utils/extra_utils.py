"""
Extra utilities module for OSINT CLI Tool.
Includes useful tools like hash analysis, MAC address lookup, and string analyzers.
"""

import re
import json
import socket
import hashlib
import string
import random
import urllib.parse
from datetime import datetime

import click
import requests
import pyperclip
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, TextColumn, SpinnerColumn

from osint_tool.config import get_api_key, get_setting
from osint_tool.modules.utils import export_utils

console = Console()

# Define the Click command group
@click.group(name="utils")
def utils_commands():
    """Additional utility commands for OSINT operations."""
    pass


@utils_commands.command(name="hash")
@click.argument("input_string")
@click.option("--algorithm", "-a", 
              type=click.Choice(["md5", "sha1", "sha256", "sha512", "all"]),
              default="all", help="Hash algorithm to use")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
@click.option("--check", "-c", is_flag=True, help="Check if provided string is a hash and identify its type")
def hash_string(input_string, algorithm, save, format, check):
    """
    Calculate hash of a string or identify a hash.
    
    INPUT_STRING: The string to hash or the hash to identify.
    """
    # Handle hash identification if --check is specified
    if check:
        hash_info = identify_hash(input_string)
        if hash_info:
            console.print(f"[green]Input appears to be a {hash_info['name']} hash.[/green]")
            console.print(f"[cyan]Bit length:[/cyan] {hash_info['bit_length']}")
            console.print(f"[cyan]Character length:[/cyan] {hash_info['char_length']}")
            console.print(f"[cyan]Example regex pattern:[/cyan] {hash_info['regex']}")
            
            # Try to look up the hash online
            known_hash = lookup_hash(input_string)
            if known_hash:
                console.print(f"[green]Hash found in online database![/green]")
                console.print(f"[cyan]Plain text:[/cyan] {known_hash}")
            
            # Save if requested
            if save:
                result_data = {
                    "input_hash": input_string,
                    "hash_type": hash_info['name'],
                    "bit_length": hash_info['bit_length'],
                    "char_length": hash_info['char_length'],
                    "known_value": known_hash if known_hash else "Not found"
                }
                
                if format == "json":
                    export_utils.save_to_json(result_data, "hash_analysis", input_string[:10])
                else:
                    export_utils.save_to_csv(result_data, "hash_analysis", input_string[:10])
            
            return
        else:
            console.print("[yellow]Input does not appear to be a standard hash format.[/yellow]")
            return
    
    # Calculate hashes
    result = {}
    
    if algorithm == "all" or algorithm == "md5":
        result["md5"] = hashlib.md5(input_string.encode()).hexdigest()
    
    if algorithm == "all" or algorithm == "sha1":
        result["sha1"] = hashlib.sha1(input_string.encode()).hexdigest()
    
    if algorithm == "all" or algorithm == "sha256":
        result["sha256"] = hashlib.sha256(input_string.encode()).hexdigest()
    
    if algorithm == "all" or algorithm == "sha512":
        result["sha512"] = hashlib.sha512(input_string.encode()).hexdigest()
    
    # Display results
    console.print(f"[bold]Hash results for: [cyan]{input_string}[/cyan][/bold]")
    
    table = Table()
    table.add_column("Algorithm", style="cyan")
    table.add_column("Hash", style="green")
    
    for algo, hash_value in result.items():
        table.add_row(algo.upper(), hash_value)
    
    console.print(table)
    
    # Save if requested
    if save:
        result["input_string"] = input_string
        
        if format == "json":
            export_utils.save_to_json(result, "hash_results", input_string[:10])
        else:
            export_utils.save_to_csv(result, "hash_results", input_string[:10])


@utils_commands.command(name="mac")
@click.argument("mac_address")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
def lookup_mac(mac_address, save, format):
    """
    Look up information about a MAC address.
    
    MAC_ADDRESS: The MAC address to look up (formats: 00:11:22:33:44:55, 00-11-22-33-44-55, 001122334455).
    """
    # Clean and validate the MAC address
    mac = clean_mac_address(mac_address)
    if not mac:
        console.print("[red]Invalid MAC address format.[/red]")
        return
    
    console.print(f"[bold]Looking up MAC address: [cyan]{mac}[/cyan][/bold]")
    
    # Look up the MAC address
    result = get_mac_info(mac)
    
    if not result:
        console.print("[yellow]No information found for this MAC address.[/yellow]")
        return
    
    # Display results
    display_mac_results(result, mac)
    
    # Save if requested
    if save:
        if format == "json":
            export_utils.save_to_json(result, "mac_lookup", mac.replace(":", ""))
        else:
            export_utils.save_to_csv(result, "mac_lookup", mac.replace(":", ""))


@utils_commands.command(name="url")
@click.argument("url")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
@click.option("--decode", "-d", is_flag=True, help="Decode a URL-encoded string")
@click.option("--encode", "-e", is_flag=True, help="Encode a string for URL use")
def analyze_url(url, save, format, decode, encode):
    """
    Analyze, encode or decode a URL.
    
    URL: The URL to analyze or string to encode/decode.
    """
    # Handle encoding/decoding
    if encode:
        encoded = urllib.parse.quote_plus(url)
        console.print(f"[bold]URL encoded string:[/bold] [cyan]{encoded}[/cyan]")
        
        # Copy to clipboard
        try:
            pyperclip.copy(encoded)
            console.print("[green]Encoded string copied to clipboard.[/green]")
        except:
            pass
        
        return
    
    if decode:
        try:
            decoded = urllib.parse.unquote_plus(url)
            console.print(f"[bold]URL decoded string:[/bold] [cyan]{decoded}[/cyan]")
            
            # Copy to clipboard
            try:
                pyperclip.copy(decoded)
                console.print("[green]Decoded string copied to clipboard.[/green]")
            except:
                pass
        except Exception as e:
            console.print(f"[red]Error decoding URL: {e}[/red]")
        
        return
    
    # Analyze URL
    console.print(f"[bold]Analyzing URL: [cyan]{url}[/cyan][/bold]")
    
    # Parse the URL
    try:
        parsed = urllib.parse.urlparse(url)
        
        # Build result data
        result = {
            "url": url,
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "params": parsed.params,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "query_params": {}
        }
        
        # Parse query parameters
        if parsed.query:
            query_params = urllib.parse.parse_qs(parsed.query)
            # Convert lists to strings for display
            for key, value in query_params.items():
                result["query_params"][key] = value[0] if len(value) == 1 else value
        
        # Display results
        display_url_analysis(result)
        
        # Save if requested
        if save:
            if format == "json":
                export_utils.save_to_json(result, "url_analysis", parsed.netloc.replace(".", "_"))
            else:
                # Flatten query params for CSV
                flat_result = {k: v for k, v in result.items() if k != "query_params"}
                for key, value in result["query_params"].items():
                    flat_result[f"param_{key}"] = value if isinstance(value, str) else json.dumps(value)
                
                export_utils.save_to_csv(flat_result, "url_analysis", parsed.netloc.replace(".", "_"))
        
    except Exception as e:
        console.print(f"[red]Error analyzing URL: {e}[/red]")


@utils_commands.command(name="random")
@click.option("--length", "-l", type=int, default=16, help="Length of the random string")
@click.option("--type", "-t", 
              type=click.Choice(["password", "uuid", "hex", "base64", "numeric", "letters", "alphanumeric", "special"]),
              default="password", help="Type of random string to generate")
@click.option("--count", "-c", type=int, default=1, help="Number of random strings to generate")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
def generate_random(length, type, count, save, format):
    """Generate random strings, passwords, UUIDs, etc."""
    if count < 1:
        console.print("[red]Count must be at least 1.[/red]")
        return
    
    if count > 100:
        console.print("[yellow]Limiting count to 100 to prevent excessive output.[/yellow]")
        count = 100
    
    # Generate random strings
    results = []
    
    console.print(f"[bold]Generating {count} random {type}(s) of length {length}:[/bold]")
    
    for i in range(count):
        random_string = generate_random_string(length, type)
        results.append(random_string)
        console.print(f"[cyan]{i+1}.[/cyan] {random_string}")
    
    # Copy first result to clipboard
    try:
        pyperclip.copy(results[0])
        console.print("[green]First item copied to clipboard.[/green]")
    except:
        pass
    
    # Save if requested
    if save:
        result_data = {
            "type": type,
            "length": length,
            "count": count,
            "items": results
        }
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == "json":
            export_utils.save_to_json(result_data, "random_strings", timestamp)
        else:
            # Prepare data for CSV
            csv_data = []
            for i, item in enumerate(results):
                csv_data.append({
                    "index": i+1,
                    "value": item,
                    "type": type,
                    "length": length
                })
            
            export_utils.save_to_csv(csv_data, "random_strings", timestamp)


@utils_commands.command(name="base64")
@click.argument("input_string")
@click.option("--decode", "-d", is_flag=True, help="Decode a base64 string")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
def base64_tool(input_string, decode, save):
    """
    Encode or decode a string using Base64.
    
    INPUT_STRING: The string to encode or decode.
    """
    import base64
    
    if decode:
        # Decode base64
        try:
            # Add padding if needed
            padded_input = input_string
            missing_padding = len(input_string) % 4
            if missing_padding:
                padded_input += "=" * (4 - missing_padding)
            
            decoded = base64.b64decode(padded_input).decode("utf-8")
            console.print(f"[bold]Base64 decoded:[/bold] [cyan]{decoded}[/cyan]")
            
            # Copy to clipboard
            try:
                pyperclip.copy(decoded)
                console.print("[green]Decoded string copied to clipboard.[/green]")
            except:
                pass
            
            # Save if requested
            if save:
                result = {
                    "input": input_string,
                    "output": decoded,
                    "operation": "decode"
                }
                export_utils.save_to_json(result, "base64_decode", decoded[:10])
            
        except Exception as e:
            console.print(f"[red]Error decoding base64: {e}[/red]")
    else:
        # Encode to base64
        try:
            encoded = base64.b64encode(input_string.encode("utf-8")).decode("utf-8")
            console.print(f"[bold]Base64 encoded:[/bold] [cyan]{encoded}[/cyan]")
            
            # Copy to clipboard
            try:
                pyperclip.copy(encoded)
                console.print("[green]Encoded string copied to clipboard.[/green]")
            except:
                pass
            
            # Save if requested
            if save:
                result = {
                    "input": input_string,
                    "output": encoded,
                    "operation": "encode"
                }
                export_utils.save_to_json(result, "base64_encode", input_string[:10])
            
        except Exception as e:
            console.print(f"[red]Error encoding to base64: {e}[/red]")


@utils_commands.command(name="cert")
@click.argument("domain")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
def check_ssl_cert(domain, save, format):
    """
    Check SSL certificate information for a domain.
    
    DOMAIN: The domain to check.
    """
    import ssl
    import socket
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from datetime import datetime
    
    console.print(f"[bold]Checking SSL certificate for: [cyan]{domain}[/cyan][/bold]")
    
    try:
        # Connect to the domain and get the certificate
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                
                # Get certificate details
                result = {
                    "domain": domain,
                    "issuer": ", ".join([f"{attr.oid._name}={attr.value}" for attr in cert.issuer]),
                    "subject": ", ".join([f"{attr.oid._name}={attr.value}" for attr in cert.subject]),
                    "version": cert.version.value,
                    "serial_number": format(cert.serial_number, 'x'),
                    "not_valid_before": cert.not_valid_before.isoformat(),
                    "not_valid_after": cert.not_valid_after.isoformat(),
                    "has_expired": datetime.now() > cert.not_valid_after,
                    "public_key_type": cert.public_key().__class__.__name__,
                }
                
                # Add alternative names if present
                try:
                    san = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    alt_names = []
                    for name in san.value:
                        if isinstance(name, x509.DNSName):
                            alt_names.append(name.value)
                    result["alternative_names"] = alt_names
                except:
                    result["alternative_names"] = []
                
                # Display results
                display_ssl_cert_info(result)
                
                # Save if requested
                if save:
                    if format == "json":
                        export_utils.save_to_json(result, "ssl_cert", domain.replace(".", "_"))
                    else:
                        # Flatten alternative names for CSV
                        flat_result = {k: v for k, v in result.items() if k != "alternative_names"}
                        if result["alternative_names"]:
                            flat_result["alternative_names"] = ", ".join(result["alternative_names"])
                        
                        export_utils.save_to_csv(flat_result, "ssl_cert", domain.replace(".", "_"))
    
    except Exception as e:
        console.print(f"[red]Error checking SSL certificate: {e}[/red]")


def identify_hash(hash_string):
    """Identify the type of hash based on its format and length."""
    # Common hash patterns
    hash_patterns = [
        {"name": "MD5", "regex": r"^[a-fA-F0-9]{32}$", "bit_length": 128, "char_length": 32},
        {"name": "SHA-1", "regex": r"^[a-fA-F0-9]{40}$", "bit_length": 160, "char_length": 40},
        {"name": "SHA-256", "regex": r"^[a-fA-F0-9]{64}$", "bit_length": 256, "char_length": 64},
        {"name": "SHA-512", "regex": r"^[a-fA-F0-9]{128}$", "bit_length": 512, "char_length": 128},
        {"name": "SHA-384", "regex": r"^[a-fA-F0-9]{96}$", "bit_length": 384, "char_length": 96},
        {"name": "SHA3-256", "regex": r"^[a-fA-F0-9]{64}$", "bit_length": 256, "char_length": 64},
        {"name": "SHA3-512", "regex": r"^[a-fA-F0-9]{128}$", "bit_length": 512, "char_length": 128}
    ]
    
    for hash_pattern in hash_patterns:
        if re.match(hash_pattern["regex"], hash_string):
            return hash_pattern
    
    return None


def lookup_hash(hash_string):
    """Check if a hash exists in online databases."""
    with console.status("Looking up hash online..."):
        # Try to look it up using various online services
        try:
            # Use a free API to check for hash
            response = requests.get(
                f"https://api.dehash.lt/api.php?search={hash_string}",
                headers={"User-Agent": get_setting("user_agent")},
                timeout=get_setting("timeout")
            )
            
            if response.status_code == 200:
                data = response.json()
                if data and data.get('success') and data.get('found') and data.get('hashes'):
                    for hash_data in data.get('hashes', []):
                        if hash_data.get('hash') == hash_string and hash_data.get('plaintext'):
                            return hash_data.get('plaintext')
            
            return None
        except:
            return None


def clean_mac_address(mac_address):
    """Clean and validate a MAC address."""
    # Remove separators
    mac = mac_address.replace(":", "").replace("-", "").replace(".", "").upper()
    
    # Check if the result is a valid MAC address
    if re.match(r"^[0-9A-F]{12}$", mac):
        # Format with colons
        return ":".join([mac[i:i+2] for i in range(0, 12, 2)])
    
    return None


def get_mac_info(mac_address):
    """Get information about a MAC address vendor."""
    with console.status("Looking up MAC address information..."):
        try:
            # Use MAC vendor lookup API
            response = requests.get(
                f"https://api.macvendors.com/{mac_address}",
                headers={"User-Agent": get_setting("user_agent")},
                timeout=get_setting("timeout")
            )
            
            if response.status_code == 200:
                vendor = response.text
                
                # Get additional information
                oui = mac_address[:8].replace(":", "")
                mac_type = "UAA (Universally Administered Address)"
                
                # Check if it's a LAA (Locally Administered Address)
                second_char = mac_address[1:2]
                binary = bin(int(second_char, 16))[2:].zfill(4)
                if binary[0] == "1":
                    mac_type = "LAA (Locally Administered Address)"
                
                # Check if it's a multicast address
                first_char = mac_address[0:1]
                binary = bin(int(first_char, 16))[2:].zfill(4)
                is_multicast = binary[0] == "1"
                
                return {
                    "mac_address": mac_address,
                    "vendor": vendor,
                    "oui": oui,
                    "is_multicast": is_multicast,
                    "address_type": mac_type
                }
            else:
                return {
                    "mac_address": mac_address,
                    "vendor": "Unknown vendor",
                    "oui": mac_address[:8].replace(":", ""),
                    "is_multicast": None,
                    "address_type": None
                }
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return None


def display_mac_results(result, mac_address):
    """Display MAC address lookup results."""
    console.print(f"\n[bold]MAC Address:[/bold] [cyan]{mac_address}[/cyan]")
    console.print(f"[bold]Vendor:[/bold] [green]{result.get('vendor', 'Unknown')}[/green]")
    console.print(f"[bold]OUI:[/bold] {result.get('oui', '')}")
    
    if result.get('address_type'):
        console.print(f"[bold]Address Type:[/bold] {result.get('address_type')}")
    
    if result.get('is_multicast') is not None:
        multicast = "Yes" if result.get('is_multicast') else "No"
        console.print(f"[bold]Multicast:[/bold] {multicast}")


def display_url_analysis(result):
    """Display URL analysis results."""
    # Create a panel for the URL components
    components = []
    
    if result["scheme"]:
        components.append(f"[cyan]Scheme:[/cyan] {result['scheme']}")
    
    if result["netloc"]:
        components.append(f"[cyan]Domain:[/cyan] {result['netloc']}")
    
    if result["path"]:
        components.append(f"[cyan]Path:[/cyan] {result['path']}")
    
    if result["params"]:
        components.append(f"[cyan]Parameters:[/cyan] {result['params']}")
    
    if result["fragment"]:
        components.append(f"[cyan]Fragment:[/cyan] {result['fragment']}")
    
    components_panel = Panel(
        "\n".join(components),
        title="URL Components",
        border_style="blue"
    )
    
    console.print(components_panel)
    
    # Display query parameters if present
    if result["query_params"]:
        console.print("\n[bold]Query Parameters:[/bold]")
        
        table = Table()
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in result["query_params"].items():
            # Convert value to string for display
            if isinstance(value, list):
                display_value = ", ".join(value)
            else:
                display_value = str(value)
            
            table.add_row(key, display_value)
        
        console.print(table)


def generate_random_string(length, type):
    """Generate a random string of the specified type and length."""
    if type == "uuid":
        import uuid
        return str(uuid.uuid4())
    
    if type == "password":
        # Mix of all character types
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))
    
    if type == "hex":
        chars = string.hexdigits.lower()
        return ''.join(random.choice(chars) for _ in range(length))
    
    if type == "base64":
        import base64
        # Generate random bytes
        random_bytes = bytes(random.getrandbits(8) for _ in range(length))
        # Encode as base64
        return base64.b64encode(random_bytes).decode('utf-8')[:length]
    
    if type == "numeric":
        chars = string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    if type == "letters":
        chars = string.ascii_letters
        return ''.join(random.choice(chars) for _ in range(length))
    
    if type == "alphanumeric":
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    if type == "special":
        chars = string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))
    
    # Default to alphanumeric
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def display_ssl_cert_info(result):
    """Display SSL certificate information."""
    # Create a panel with the certificate details
    cert_info = []
    
    cert_info.append(f"[cyan]Domain:[/cyan] {result['domain']}")
    cert_info.append(f"[cyan]Subject:[/cyan] {result['subject']}")
    cert_info.append(f"[cyan]Issuer:[/cyan] {result['issuer']}")
    cert_info.append(f"[cyan]Valid From:[/cyan] {result['not_valid_before']}")
    cert_info.append(f"[cyan]Valid Until:[/cyan] {result['not_valid_after']}")
    
    if result['has_expired']:
        cert_info.append(f"[red]Certificate has expired![/red]")
    else:
        cert_info.append(f"[green]Certificate is valid.[/green]")
    
    cert_info.append(f"[cyan]Version:[/cyan] {result['version']}")
    cert_info.append(f"[cyan]Serial Number:[/cyan] {result['serial_number']}")
    cert_info.append(f"[cyan]Public Key Type:[/cyan] {result['public_key_type']}")
    
    if result['alternative_names']:
        cert_info.append("\n[cyan]Alternative Names:[/cyan]")
        for name in result['alternative_names']:
            cert_info.append(f"- {name}")
    
    cert_panel = Panel(
        "\n".join(cert_info),
        title=f"SSL Certificate for {result['domain']}",
        border_style="blue"
    )
    
    console.print(cert_panel) 