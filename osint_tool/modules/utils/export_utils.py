"""
Export utilities for saving OSINT results to various formats.
"""
import os
import json
import csv
from datetime import datetime
from pathlib import Path

from rich.console import Console

console = Console()


def get_output_filename(prefix, target, extension):
    """
    Generate a unique filename for output.
    
    Args:
        prefix (str): Type of scan (e.g., 'username', 'ip', 'domain')
        target (str): The target of the scan
        extension (str): File extension
        
    Returns:
        Path: The full path to the output file
    """
    from osint_tool.config import get_setting
    
    # Get output directory from config
    output_dir = get_setting("output_directory")
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Clean target for use in filename
    safe_target = "".join(c if c.isalnum() else "_" for c in target)
    
    # Create filename
    filename = f"{prefix}_{safe_target}_{timestamp}.{extension}"
    return Path(output_dir) / filename


def save_to_json(data, prefix, target):
    """
    Save data to a JSON file.
    
    Args:
        data (dict): The data to save
        prefix (str): Type of scan
        target (str): The target of the scan
        
    Returns:
        str: Path to the saved file
    """
    try:
        output_file = get_output_filename(prefix, target, "json")
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, default=str)
        
        console.print(f"[green]Results saved to {output_file}[/green]")
        return str(output_file)
    
    except Exception as e:
        console.print(f"[red]Error saving to JSON: {e}[/red]")
        return None


def save_to_csv(data, prefix, target, headers=None):
    """
    Save data to a CSV file.
    
    Args:
        data (list): List of dictionaries to save
        prefix (str): Type of scan
        target (str): The target of the scan
        headers (list, optional): List of column headers
        
    Returns:
        str: Path to the saved file
    """
    try:
        output_file = get_output_filename(prefix, target, "csv")
        
        # If data is a dictionary, convert to list of dicts
        if isinstance(data, dict):
            # If it's a simple dict, wrap it
            if not any(isinstance(v, dict) for v in data.values()):
                data = [data]
            # If it's a nested dict, flatten it
            else:
                flattened = []
                for key, value in data.items():
                    if isinstance(value, dict):
                        value['key'] = key
                        flattened.append(value)
                    else:
                        flattened.append({'key': key, 'value': value})
                data = flattened
        
        # If no headers provided, use the keys from the first item
        if not headers and data:
            headers = list(data[0].keys())
        
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data)
        
        console.print(f"[green]Results saved to {output_file}[/green]")
        return str(output_file)
    
    except Exception as e:
        console.print(f"[red]Error saving to CSV: {e}[/red]")
        return None 