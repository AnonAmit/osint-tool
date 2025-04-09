"""
GitHub Intelligence module for OSINT CLI Tool.
Includes GitHub user profile analysis and repository searches.
"""

import re
import json
import base64
from urllib.parse import quote

import click
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from osint_tool.config import get_api_key, get_setting
from osint_tool.modules.utils import export_utils

console = Console()

# Define the Click command group
@click.group(name="github")
def github_commands():
    """Commands for GitHub intelligence gathering."""
    pass


@github_commands.command(name="user")
@click.argument("username")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
@click.option("--repos", "-r", is_flag=True, help="Include repositories information")
@click.option("--orgs", "-o", is_flag=True, help="Include organizations information")
@click.option("--contributions", "-c", is_flag=True, help="Include contributions information")
def check_github_user(username, save, format, repos, orgs, contributions):
    """
    Check a GitHub user profile.
    
    USERNAME: The GitHub username to look up.
    """
    console.print(f"[bold]Looking up GitHub user: [cyan]{username}[/cyan][/bold]")
    
    # Get API key (optional, increases rate limits)
    api_key = get_api_key("github")
    
    # Get user information
    user_data = get_github_user(username, api_key)
    
    if not user_data:
        console.print(f"[yellow]No GitHub user found with username: [bold]{username}[/bold][/yellow]")
        return
    
    # Get repositories if requested
    if repos:
        repos_data = get_github_repos(username, api_key)
        if repos_data:
            user_data["repositories"] = repos_data
    
    # Get organizations if requested
    if orgs:
        orgs_data = get_github_orgs(username, api_key)
        if orgs_data:
            user_data["organizations"] = orgs_data
    
    # Get contribution information if requested
    if contributions:
        contrib_data = get_github_contributions(username, api_key)
        if contrib_data:
            user_data["contributions"] = contrib_data
    
    # Display results
    display_github_user(user_data, username)
    
    # Save if requested
    if save:
        if format == "json":
            export_utils.save_to_json(user_data, "github_user", username)
        else:
            # Flatten user data for CSV
            flat_data = {}
            for key, value in user_data.items():
                if isinstance(value, (str, int, float, bool)) or value is None:
                    flat_data[key] = value
            
            export_utils.save_to_csv(flat_data, "github_user", username)
            
            # If repos were requested, save them separately
            if repos and "repositories" in user_data:
                export_utils.save_to_csv(user_data["repositories"], "github_repos", username)


@github_commands.command(name="repo")
@click.argument("repository")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
@click.option("--contributors", "-c", is_flag=True, help="Include contributors information")
@click.option("--commits", "-m", is_flag=True, help="Include recent commits")
def check_github_repo(repository, save, format, contributors, commits):
    """
    Check a GitHub repository.
    
    REPOSITORY: The GitHub repository to look up (format: owner/repo).
    """
    # Check if the repository format is valid
    if "/" not in repository:
        console.print("[red]Invalid repository format. Please use 'owner/repo' format.[/red]")
        return
    
    console.print(f"[bold]Looking up GitHub repository: [cyan]{repository}[/cyan][/bold]")
    
    # Get API key (optional, increases rate limits)
    api_key = get_api_key("github")
    
    # Get repository information
    repo_data = get_github_repo(repository, api_key)
    
    if not repo_data:
        console.print(f"[yellow]No GitHub repository found with name: [bold]{repository}[/bold][/yellow]")
        return
    
    # Get contributors if requested
    if contributors:
        contrib_data = get_github_repo_contributors(repository, api_key)
        if contrib_data:
            repo_data["contributors"] = contrib_data
    
    # Get recent commits if requested
    if commits:
        commits_data = get_github_repo_commits(repository, api_key)
        if commits_data:
            repo_data["recent_commits"] = commits_data
    
    # Display results
    display_github_repo(repo_data, repository)
    
    # Save if requested
    if save:
        if format == "json":
            export_utils.save_to_json(repo_data, "github_repo", repository.replace("/", "_"))
        else:
            # Flatten repo data for CSV
            flat_data = {}
            for key, value in repo_data.items():
                if isinstance(value, (str, int, float, bool)) or value is None:
                    flat_data[key] = value
            
            export_utils.save_to_csv(flat_data, "github_repo", repository.replace("/", "_"))
            
            # If contributors were requested, save them separately
            if contributors and "contributors" in repo_data:
                export_utils.save_to_csv(repo_data["contributors"], "github_contributors", repository.replace("/", "_"))


@github_commands.command(name="dork")
@click.argument("query")
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
@click.option("--type", "-t", 
              type=click.Choice(["code", "repos", "issues", "custom"]), 
              default="code", help="Type of search to perform")
def github_dork(query, save, format, type):
    """
    Search GitHub for sensitive information using GitHub dorks.
    
    QUERY: The search query or predefined dork name.
    """
    console.print(f"[bold]Searching GitHub for: [cyan]{query}[/cyan][/bold]")
    
    # Get API key (optional, increases rate limits)
    api_key = get_api_key("github")
    
    # Check if the query is a predefined dork
    final_query = get_predefined_dork(query, type)
    if final_query != query:
        console.print(f"[blue]Using predefined dork: [bold]{final_query}[/bold][/blue]")
    
    # Perform the search
    results = search_github(final_query, type, api_key)
    
    if not results:
        console.print(f"[yellow]No results found for query: [bold]{final_query}[/bold][/yellow]")
        return
    
    # Display results
    display_github_search(results, final_query, type)
    
    # Save if requested
    if save:
        if format == "json":
            export_utils.save_to_json(results, "github_search", clean_filename(final_query))
        else:
            # Flatten items for CSV
            flat_items = []
            
            if type == "code":
                for item in results.get("items", []):
                    flat_item = {
                        "repository": item.get("repository", {}).get("full_name", ""),
                        "path": item.get("path", ""),
                        "url": item.get("html_url", ""),
                        "score": item.get("score", "")
                    }
                    flat_items.append(flat_item)
            else:
                for item in results.get("items", []):
                    flat_item = {
                        "name": item.get("name", ""),
                        "full_name": item.get("full_name", ""),
                        "url": item.get("html_url", ""),
                        "description": item.get("description", ""),
                        "stars": item.get("stargazers_count", ""),
                        "forks": item.get("forks_count", "")
                    }
                    flat_items.append(flat_item)
            
            export_utils.save_to_csv(flat_items, "github_search", clean_filename(final_query))


def get_github_user(username, api_key=None):
    """Get information about a GitHub user."""
    headers = {
        "User-Agent": get_setting("user_agent")
    }
    
    if api_key:
        headers["Authorization"] = f"token {api_key}"
    
    with console.status(f"Getting GitHub user information for {username}..."):
        try:
            response = requests.get(
                f"https://api.github.com/users/{username}",
                headers=headers,
                timeout=get_setting("timeout")
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                console.print(f"[red]Error from GitHub API: {response.status_code} - {response.text}[/red]")
                return None
                
        except Exception as e:
            console.print(f"[red]Error getting GitHub user: {e}[/red]")
            return None


def get_github_repos(username, api_key=None):
    """Get repositories for a GitHub user."""
    headers = {
        "User-Agent": get_setting("user_agent")
    }
    
    if api_key:
        headers["Authorization"] = f"token {api_key}"
    
    with console.status(f"Getting repositories for {username}..."):
        try:
            # Set up pagination
            page = 1
            per_page = 100
            all_repos = []
            
            while True:
                response = requests.get(
                    f"https://api.github.com/users/{username}/repos?page={page}&per_page={per_page}",
                    headers=headers,
                    timeout=get_setting("timeout")
                )
                
                if response.status_code == 200:
                    repos = response.json()
                    if not repos:
                        break
                    
                    all_repos.extend(repos)
                    page += 1
                    
                    # Stop after a reasonable number of pages to avoid rate limiting
                    if page > 5:
                        console.print("[yellow]Limiting to 500 repositories to avoid rate limiting.[/yellow]")
                        break
                else:
                    console.print(f"[red]Error from GitHub API: {response.status_code} - {response.text}[/red]")
                    break
            
            return all_repos
                
        except Exception as e:
            console.print(f"[red]Error getting repositories: {e}[/red]")
            return None


def get_github_orgs(username, api_key=None):
    """Get organizations for a GitHub user."""
    headers = {
        "User-Agent": get_setting("user_agent")
    }
    
    if api_key:
        headers["Authorization"] = f"token {api_key}"
    
    with console.status(f"Getting organizations for {username}..."):
        try:
            response = requests.get(
                f"https://api.github.com/users/{username}/orgs",
                headers=headers,
                timeout=get_setting("timeout")
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                console.print(f"[red]Error from GitHub API: {response.status_code} - {response.text}[/red]")
                return None
                
        except Exception as e:
            console.print(f"[red]Error getting organizations: {e}[/red]")
            return None


def get_github_contributions(username, api_key=None):
    """Get contribution information for a GitHub user (requires web scraping)."""
    headers = {
        "User-Agent": get_setting("user_agent")
    }
    
    with console.status(f"Getting contribution information for {username}..."):
        try:
            # This information is not directly available from the API
            # We'll use a simple summary based on repositories and events
            
            # Get user events
            if api_key:
                headers["Authorization"] = f"token {api_key}"
            
            response = requests.get(
                f"https://api.github.com/users/{username}/events",
                headers=headers,
                timeout=get_setting("timeout")
            )
            
            if response.status_code == 200:
                events = response.json()
                
                # Count event types
                event_counts = {}
                for event in events:
                    event_type = event.get("type", "Unknown")
                    event_counts[event_type] = event_counts.get(event_type, 0) + 1
                
                return {
                    "recent_events": event_counts,
                    "total_recent_events": len(events)
                }
            else:
                console.print(f"[yellow]Could not get contribution information: {response.status_code}[/yellow]")
                return None
                
        except Exception as e:
            console.print(f"[red]Error getting contributions: {e}[/red]")
            return None


def get_github_repo(repository, api_key=None):
    """Get information about a GitHub repository."""
    headers = {
        "User-Agent": get_setting("user_agent")
    }
    
    if api_key:
        headers["Authorization"] = f"token {api_key}"
    
    with console.status(f"Getting GitHub repository information for {repository}..."):
        try:
            response = requests.get(
                f"https://api.github.com/repos/{repository}",
                headers=headers,
                timeout=get_setting("timeout")
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                console.print(f"[red]Error from GitHub API: {response.status_code} - {response.text}[/red]")
                return None
                
        except Exception as e:
            console.print(f"[red]Error getting GitHub repository: {e}[/red]")
            return None


def get_github_repo_contributors(repository, api_key=None):
    """Get contributors for a GitHub repository."""
    headers = {
        "User-Agent": get_setting("user_agent")
    }
    
    if api_key:
        headers["Authorization"] = f"token {api_key}"
    
    with console.status(f"Getting contributors for {repository}..."):
        try:
            response = requests.get(
                f"https://api.github.com/repos/{repository}/contributors",
                headers=headers,
                timeout=get_setting("timeout")
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                console.print(f"[red]Error from GitHub API: {response.status_code} - {response.text}[/red]")
                return None
                
        except Exception as e:
            console.print(f"[red]Error getting contributors: {e}[/red]")
            return None


def get_github_repo_commits(repository, api_key=None):
    """Get recent commits for a GitHub repository."""
    headers = {
        "User-Agent": get_setting("user_agent")
    }
    
    if api_key:
        headers["Authorization"] = f"token {api_key}"
    
    with console.status(f"Getting recent commits for {repository}..."):
        try:
            # Get only the last 30 commits to avoid rate limiting
            response = requests.get(
                f"https://api.github.com/repos/{repository}/commits?per_page=30",
                headers=headers,
                timeout=get_setting("timeout")
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                console.print(f"[red]Error from GitHub API: {response.status_code} - {response.text}[/red]")
                return None
                
        except Exception as e:
            console.print(f"[red]Error getting commits: {e}[/red]")
            return None


def get_predefined_dork(query, type):
    """Get a predefined GitHub dork query."""
    # Dictionary of predefined dorks
    predefined_dorks = {
        # Secrets and API keys
        "aws_key": "AWS_ACCESS_KEY_ID",
        "aws_secret": "AWS_SECRET_ACCESS_KEY",
        "private_key": "-----BEGIN PRIVATE KEY-----",
        "ssh_private_key": "-----BEGIN RSA PRIVATE KEY-----",
        "github_token": "github_token",
        "api_key": "apikey",
        "password": "password",
        "secret": "secret",
        
        # Configuration files
        "config": "filename:config",
        "env": "filename:.env",
        "credentials": "filename:credentials",
        
        # Database connection strings
        "mongodb": "mongodb://",
        "postgres": "postgresql://",
        "mysql": "mysql://",
        
        # Interesting files
        "todo": "filename:todo",
        "backup": "filename:backup",
        "dump": "filename:dump",
        
        # Security vulnerabilities
        "sql_injection": "execute(\"SELECT * FROM",
        "xss": "innerHTML",
        "rce": "exec("
    }
    
    # If the query is a predefined dork, return the actual query
    if query.lower() in predefined_dorks:
        return predefined_dorks[query.lower()]
    
    # Otherwise return the original query
    return query


def search_github(query, type, api_key=None):
    """Search GitHub for code, repositories, or issues."""
    headers = {
        "User-Agent": get_setting("user_agent")
    }
    
    if api_key:
        headers["Authorization"] = f"token {api_key}"
    
    with console.status(f"Searching GitHub for {query}..."):
        try:
            # Determine the search endpoint based on type
            if type == "code":
                endpoint = "code"
            elif type == "repos":
                endpoint = "repositories"
            elif type == "issues":
                endpoint = "issues"
            else:  # custom
                endpoint = "code"
            
            # Encode the query
            encoded_query = quote(query)
            
            response = requests.get(
                f"https://api.github.com/search/{endpoint}?q={encoded_query}&per_page=100",
                headers=headers,
                timeout=get_setting("timeout") * 2  # Search can take longer
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 403 and "rate limit" in response.text.lower():
                console.print("[red]GitHub API rate limit exceeded. Try again later or use an API key.[/red]")
                return None
            else:
                console.print(f"[red]Error from GitHub API: {response.status_code} - {response.text}[/red]")
                return None
                
        except Exception as e:
            console.print(f"[red]Error searching GitHub: {e}[/red]")
            return None


def display_github_user(user_data, username):
    """Display GitHub user information."""
    if not user_data:
        return
    
    # Create and display a panel with basic user info
    name = user_data.get("name", "")
    bio = user_data.get("bio", "")
    location = user_data.get("location", "")
    company = user_data.get("company", "")
    email = user_data.get("email", "")
    blog = user_data.get("blog", "")
    twitter = user_data.get("twitter_username", "")
    public_repos = user_data.get("public_repos", 0)
    public_gists = user_data.get("public_gists", 0)
    followers = user_data.get("followers", 0)
    following = user_data.get("following", 0)
    created_at = user_data.get("created_at", "")
    
    info = []
    
    if name:
        info.append(f"[cyan]Name:[/cyan] {name}")
    if bio:
        info.append(f"[cyan]Bio:[/cyan] {bio}")
    if location:
        info.append(f"[cyan]Location:[/cyan] {location}")
    if company:
        info.append(f"[cyan]Company:[/cyan] {company}")
    if email:
        info.append(f"[cyan]Email:[/cyan] {email}")
    if blog:
        info.append(f"[cyan]Website:[/cyan] {blog}")
    if twitter:
        info.append(f"[cyan]Twitter:[/cyan] @{twitter}")
    
    info.append("")
    info.append(f"[cyan]Public Repositories:[/cyan] {public_repos}")
    info.append(f"[cyan]Public Gists:[/cyan] {public_gists}")
    info.append(f"[cyan]Followers:[/cyan] {followers}")
    info.append(f"[cyan]Following:[/cyan] {following}")
    info.append(f"[cyan]Created:[/cyan] {created_at}")
    
    info_panel = Panel(
        "\n".join(info),
        title=f"GitHub User: [bold]{username}[/bold]",
        border_style="blue"
    )
    
    console.print(info_panel)
    
    # Display repositories if available
    if "repositories" in user_data and user_data["repositories"]:
        repos = user_data["repositories"]
        
        # Create a table for the repositories
        table = Table(title=f"Repositories for [bold cyan]{username}[/bold cyan]")
        
        table.add_column("Repository", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Language", style="yellow")
        table.add_column("Stars", style="magenta")
        table.add_column("Forks", style="blue")
        
        # Sort repositories by stars (descending)
        sorted_repos = sorted(repos, key=lambda x: x.get("stargazers_count", 0), reverse=True)
        
        # Add top 15 repositories to the table
        for repo in sorted_repos[:15]:
            name = repo.get("name", "")
            description = repo.get("description", "")
            if description and len(description) > 40:
                description = description[:37] + "..."
            language = repo.get("language", "")
            stars = str(repo.get("stargazers_count", 0))
            forks = str(repo.get("forks_count", 0))
            
            table.add_row(name, description, language, stars, forks)
        
        console.print(table)
        
        if len(repos) > 15:
            console.print(f"[yellow]Showing 15 of {len(repos)} repositories.[/yellow]")
    
    # Display organizations if available
    if "organizations" in user_data and user_data["organizations"]:
        orgs = user_data["organizations"]
        
        console.print(f"[cyan]Organizations ({len(orgs)}):[/cyan]")
        for org in orgs:
            console.print(f"- {org.get('login', '')}")
    
    # Display contributions if available
    if "contributions" in user_data and user_data["contributions"]:
        contrib = user_data["contributions"]
        
        console.print("\n[cyan]Recent Activity:[/cyan]")
        for event_type, count in contrib.get("recent_events", {}).items():
            event_name = event_type.replace("Event", "")
            console.print(f"- {event_name}: {count}")
    
    # Add link to GitHub profile
    console.print(f"\n[cyan]GitHub Profile:[/cyan] https://github.com/{username}")


def display_github_repo(repo_data, repository):
    """Display GitHub repository information."""
    if not repo_data:
        return
    
    # Create and display a panel with basic repo info
    name = repo_data.get("name", "")
    description = repo_data.get("description", "")
    language = repo_data.get("language", "")
    owner = repo_data.get("owner", {}).get("login", "")
    license_name = repo_data.get("license", {}).get("name", "")
    stars = repo_data.get("stargazers_count", 0)
    forks = repo_data.get("forks_count", 0)
    issues = repo_data.get("open_issues_count", 0)
    watchers = repo_data.get("watchers_count", 0)
    created_at = repo_data.get("created_at", "")
    updated_at = repo_data.get("updated_at", "")
    homepage = repo_data.get("homepage", "")
    
    info = []
    
    if description:
        info.append(f"[cyan]Description:[/cyan] {description}")
    if language:
        info.append(f"[cyan]Primary Language:[/cyan] {language}")
    if owner:
        info.append(f"[cyan]Owner:[/cyan] {owner}")
    if license_name:
        info.append(f"[cyan]License:[/cyan] {license_name}")
    
    info.append("")
    info.append(f"[cyan]Stars:[/cyan] {stars}")
    info.append(f"[cyan]Forks:[/cyan] {forks}")
    info.append(f"[cyan]Open Issues:[/cyan] {issues}")
    info.append(f"[cyan]Watchers:[/cyan] {watchers}")
    info.append(f"[cyan]Created:[/cyan] {created_at}")
    info.append(f"[cyan]Last Updated:[/cyan] {updated_at}")
    
    if homepage:
        info.append(f"[cyan]Homepage:[/cyan] {homepage}")
    
    info_panel = Panel(
        "\n".join(info),
        title=f"GitHub Repository: [bold]{repository}[/bold]",
        border_style="blue"
    )
    
    console.print(info_panel)
    
    # Display contributors if available
    if "contributors" in repo_data and repo_data["contributors"]:
        contributors = repo_data["contributors"]
        
        # Create a table for the contributors
        table = Table(title=f"Top Contributors to [bold cyan]{repository}[/bold cyan]")
        
        table.add_column("Username", style="cyan")
        table.add_column("Contributions", style="green")
        
        # Show only the top 10 contributors
        for contributor in contributors[:10]:
            username = contributor.get("login", "")
            contributions = str(contributor.get("contributions", 0))
            
            table.add_row(username, contributions)
        
        console.print(table)
        
        if len(contributors) > 10:
            console.print(f"[yellow]Showing 10 of {len(contributors)} contributors.[/yellow]")
    
    # Display recent commits if available
    if "recent_commits" in repo_data and repo_data["recent_commits"]:
        commits = repo_data["recent_commits"]
        
        # Create a table for the commits
        table = Table(title=f"Recent Commits to [bold cyan]{repository}[/bold cyan]")
        
        table.add_column("Author", style="cyan")
        table.add_column("Message", style="green")
        table.add_column("Date", style="yellow")
        
        # Show only the last 10 commits
        for commit in commits[:10]:
            author = commit.get("commit", {}).get("author", {}).get("name", "")
            message = commit.get("commit", {}).get("message", "").split("\n")[0]  # First line of message
            if len(message) > 50:
                message = message[:47] + "..."
            date = commit.get("commit", {}).get("author", {}).get("date", "")
            
            table.add_row(author, message, date)
        
        console.print(table)
    
    # Add link to GitHub repository
    console.print(f"\n[cyan]GitHub Repository:[/cyan] https://github.com/{repository}")


def display_github_search(results, query, type):
    """Display GitHub search results."""
    if not results:
        return
    
    total_count = results.get("total_count", 0)
    items = results.get("items", [])
    
    console.print(f"[green]Found {total_count} results for query: [bold]{query}[/bold][/green]")
    
    if type == "code":
        # Create a table for code search results
        table = Table(title=f"Code Search Results for [bold cyan]{query}[/bold cyan]")
        
        table.add_column("Repository", style="cyan")
        table.add_column("File", style="green")
        table.add_column("Path", style="yellow")
        
        # Show only the top 20 results
        for item in items[:20]:
            repo_name = item.get("repository", {}).get("full_name", "")
            file_name = item.get("name", "")
            path = item.get("path", "")
            
            table.add_row(repo_name, file_name, path)
        
        console.print(table)
    else:
        # Create a table for repository search results
        table = Table(title=f"Repository Search Results for [bold cyan]{query}[/bold cyan]")
        
        table.add_column("Repository", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Stars", style="yellow")
        table.add_column("Language", style="magenta")
        
        # Show only the top 20 results
        for item in items[:20]:
            repo_name = item.get("full_name", "")
            description = item.get("description", "")
            if description and len(description) > 40:
                description = description[:37] + "..."
            stars = str(item.get("stargazers_count", 0))
            language = item.get("language", "")
            
            table.add_row(repo_name, description, stars, language)
        
        console.print(table)
    
    if len(items) > 20:
        console.print(f"[yellow]Showing 20 of {len(items)} results.[/yellow]")


def clean_filename(query):
    """Clean a query string for use in a filename."""
    # Replace characters that are not allowed in filenames
    return re.sub(r'[\\/*?:"<>|]', "_", query) 