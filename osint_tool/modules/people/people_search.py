"""
People search module for OSINT CLI Tool.
Includes username lookup, email rep, and breach checks.
"""

import os
import sys
import time
import json
import requests
import subprocess
from pathlib import Path
import concurrent.futures

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from osint_tool.config import get_api_key, get_setting
from osint_tool.modules.utils import export_utils

console = Console()

# Define the Click command group
@click.group(name="people")
def people_commands():
    """Commands for searching people-related information."""
    pass


@people_commands.command(name="username")
@click.argument("username")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
@click.option("--timeout", "-t", type=int, default=None, help="Timeout in seconds for requests")
def search_username(username, save, format, timeout):
    """
    Search for a username across multiple platforms using Sherlock or direct API calls.
    
    USERNAME: The username to search for.
    """
    console.print(f"[bold]Searching for username: [cyan]{username}[/cyan][/bold]")
    
    # Set timeout from option or config
    if timeout is None:
        timeout = get_setting("timeout")
    
    results = {}
    
    # Check if Sherlock is installed
    sherlock_installed = is_sherlock_installed()
    
    if sherlock_installed:
        # Run Sherlock for username check
        results = run_sherlock(username, timeout)
    else:
        # Fallback to basic check using our own implementation
        console.print("[yellow]Sherlock not found, falling back to basic username check...[/yellow]")
        results = basic_username_check(username, timeout)
    
    # Display results
    display_username_results(results, username)
    
    # Save if requested
    if save:
        if format == "json":
            export_utils.save_to_json(results, "username", username)
        else:
            export_utils.save_to_csv(results, "username", username)


def is_sherlock_installed():
    """Check if Sherlock is installed."""
    try:
        result = subprocess.run(
            ["sherlock", "--version"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def run_sherlock(username, timeout):
    """Run Sherlock to check username across platforms."""
    results = {}
    
    with console.status(f"Running Sherlock for {username}..."):
        try:
            # Create a temporary file for output
            output_file = Path(get_setting("output_directory")) / f"sherlock_temp_{username}.json"
            
            # Run Sherlock with JSON output
            cmd = [
                "sherlock", 
                username, 
                "--timeout", str(timeout),
                "--print-found",
                "--output", str(output_file),
                "--json"
            ]
            
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Parse output file if it exists
            if output_file.exists():
                with open(output_file, 'r') as f:
                    results = json.load(f)
                # Clean up temp file
                os.remove(output_file)
            else:
                # Parse from stdout if file wasn't created
                lines = process.stdout.strip().split('\n')
                for line in lines:
                    if "+" in line:
                        parts = line.split('+')
                        if len(parts) >= 2:
                            site = parts[1].strip().split()[0]
                            url = parts[1].strip().split()[-1]
                            results[site] = {"url_main": url, "exists": "yes"}
            
            return results
        
        except Exception as e:
            console.print(f"[red]Error running Sherlock: {e}[/red]")
            return {}


def basic_username_check(username, timeout):
    """Perform a basic username check on common platforms."""
    results = {}
    
    # List of common platforms and their URL patterns
    platforms = {
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}/",
        "GitHub": f"https://github.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Medium": f"https://medium.com/@{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/",
        "Twitch": f"https://www.twitch.tv/{username}"
    }
    
    headers = {
        "User-Agent": get_setting("user_agent")
    }
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}[/bold blue]"),
        console=console
    ) as progress:
        task = progress.add_task(f"Checking username across platforms...", total=len(platforms))
        
        # Create a thread pool to check platforms in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=get_setting("max_threads")) as executor:
            # Create a dictionary to keep track of futures
            future_to_platform = {
                executor.submit(check_platform, platform, url, headers, timeout): platform
                for platform, url in platforms.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_platform):
                platform = future_to_platform[future]
                try:
                    exists, url = future.result()
                    if exists:
                        results[platform] = {"url_main": url, "exists": "yes"}
                except Exception as e:
                    console.print(f"[red]Error checking {platform}: {e}[/red]")
                
                progress.update(task, advance=1)
    
    return results


def check_platform(platform, url, headers, timeout):
    """Check if a username exists on a specific platform."""
    try:
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        
        # Different platforms have different ways of indicating a profile exists
        if platform == "Instagram":
            return "not found" not in response.text.lower() and response.status_code != 404, url
        elif platform == "Twitter":
            return response.status_code != 404 and "page doesn't exist" not in response.text.lower(), url
        else:
            # General check
            return response.status_code == 200, url
    
    except Exception:
        return False, url


def display_username_results(results, username):
    """Display username search results in a table."""
    table = Table(title=f"Username Search Results for [bold cyan]{username}[/bold cyan]")
    
    table.add_column("Platform", style="cyan")
    table.add_column("Found", style="green")
    table.add_column("URL", style="blue")
    
    found_count = 0
    
    for platform, data in results.items():
        if data.get("exists") == "yes":
            found_count += 1
            table.add_row(
                platform,
                "✓",
                data.get("url_main", "N/A")
            )
    
    if found_count > 0:
        console.print(table)
        console.print(f"[green]Found on {found_count} platforms[/green]")
    else:
        console.print(f"[yellow]No matches found for username [bold]{username}[/bold][/yellow]")


@people_commands.command(name="email")
@click.argument("email")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
@click.option("--check-breaches", "-b", is_flag=True, help="Check for breaches (requires HIBP API key)")
def check_email(email, save, format, check_breaches):
    """
    Check email reputation and breaches.
    
    EMAIL: The email address to check.
    """
    console.print(f"[bold]Checking email: [cyan]{email}[/cyan][/bold]")
    
    results = {}
    
    # Check email reputation with emailrep.io
    email_rep = check_emailrep(email)
    if email_rep:
        results["emailrep"] = email_rep
    
    # Check breaches if requested and API key is available
    if check_breaches:
        hibp_key = get_api_key("haveibeenpwned")
        if hibp_key:
            breaches = check_haveibeenpwned(email, hibp_key)
            if breaches:
                results["breaches"] = breaches
        else:
            console.print("[yellow]HaveIBeenPwned API key not found. Skipping breach check.[/yellow]")
            console.print("[yellow]You can set it with environment variable OSINT_HAVEIBEENPWNED_API_KEY.[/yellow]")
    
    # Display results
    display_email_results(results, email)
    
    # Save if requested
    if save:
        if format == "json":
            export_utils.save_to_json(results, "email", email)
        else:
            export_utils.save_to_csv(results, "email", email)


def check_emailrep(email):
    """Check email reputation using emailrep.io."""
    api_key = get_api_key("emailrep")
    
    headers = {
        "User-Agent": get_setting("user_agent")
    }
    
    if api_key:
        headers["Key"] = api_key
    
    with console.status(f"Checking email reputation for {email}..."):
        try:
            response = requests.get(
                f"https://emailrep.io/{email}",
                headers=headers,
                timeout=get_setting("timeout")
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                console.print(f"[red]Error checking email reputation: {response.status_code} - {response.text}[/red]")
                return None
        
        except Exception as e:
            console.print(f"[red]Error checking email reputation: {e}[/red]")
            return None


def check_haveibeenpwned(email, api_key):
    """Check if email has been in a breach using HaveIBeenPwned."""
    headers = {
        "User-Agent": get_setting("user_agent"),
        "hibp-api-key": api_key
    }
    
    with console.status(f"Checking breaches for {email}..."):
        try:
            # Wait 1.5 seconds to respect rate limits
            time.sleep(1.5)
            
            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers=headers,
                timeout=get_setting("timeout")
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return []
            else:
                console.print(f"[red]Error checking breaches: {response.status_code} - {response.text}[/red]")
                return None
        
        except Exception as e:
            console.print(f"[red]Error checking breaches: {e}[/red]")
            return None


def display_email_results(results, email):
    """Display email check results."""
    if "emailrep" in results:
        rep_data = results["emailrep"]
        
        # Main table for email reputation
        table = Table(title=f"Email Reputation for [bold cyan]{email}[/bold cyan]")
        
        table.add_column("Attribute", style="cyan")
        table.add_column("Value", style="green")
        
        if "reputation" in rep_data:
            table.add_row("Reputation", rep_data["reputation"])
        
        if "suspicious" in rep_data:
            suspicious = "Yes" if rep_data["suspicious"] else "No"
            table.add_row("Suspicious", suspicious)
        
        if "details" in rep_data:
            details = rep_data["details"]
            
            if "first_seen" in details:
                table.add_row("First Seen", details["first_seen"])
            
            if "last_seen" in details:
                table.add_row("Last Seen", details["last_seen"])
            
            if "profiles" in details and details["profiles"]:
                profiles = ", ".join(details["profiles"])
                table.add_row("Profiles", profiles)
            
            if "malicious_activity" in details:
                malicious = "Yes" if details["malicious_activity"] else "No"
                table.add_row("Malicious Activity", malicious)
            
            if "credentials_leaked" in details:
                leaked = "Yes" if details["credentials_leaked"] else "No"
                table.add_row("Credentials Leaked", leaked)
            
            if "data_breach" in details:
                breach = "Yes" if details["data_breach"] else "No"
                table.add_row("Data Breach", breach)
        
        console.print(table)
    
    # Display breach information if available
    if "breaches" in results:
        breaches = results["breaches"]
        
        if breaches:
            breach_table = Table(title=f"Breaches for [bold cyan]{email}[/bold cyan]")
            
            breach_table.add_column("Breach", style="red")
            breach_table.add_column("Date", style="yellow")
            breach_table.add_column("# of Records", style="cyan")
            
            for breach in breaches:
                breach_table.add_row(
                    breach.get("Name", "Unknown"),
                    breach.get("BreachDate", "Unknown"),
                    str(breach.get("PwnCount", "Unknown"))
                )
            
            console.print(breach_table)
            console.print(f"[red]Found in {len(breaches)} breaches![/red]")
        else:
            console.print("[green]Good news! No breaches found for this email.[/green]")
    
    if not results:
        console.print(f"[yellow]No results found for email [bold]{email}[/bold][/yellow]") 