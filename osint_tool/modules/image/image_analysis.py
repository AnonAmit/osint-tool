"""
Image Analysis module for OSINT CLI Tool.
Includes EXIF data extraction and reverse image search capabilities.
"""

import os
import sys
import json
import subprocess
import webbrowser
from pathlib import Path
from urllib.parse import quote

import click
import exifread
from PIL import Image
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from osint_tool.config import get_setting
from osint_tool.modules.utils import export_utils

console = Console()

# Define the Click command group
@click.group(name="image")
def image_commands():
    """Commands for image analysis."""
    pass


@image_commands.command(name="exif")
@click.argument("image_path", type=click.Path(exists=True))
@click.option("--save", "-s", is_flag=True, help="Save results to file")
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="json", help="Output format for saved results")
@click.option("--method", "-m", type=click.Choice(["exiftool", "python", "auto"]), default="auto", 
              help="Method for extracting EXIF data")
def extract_exif(image_path, save, format, method):
    """
    Extract EXIF metadata from an image.
    
    IMAGE_PATH: Path to the image file.
    """
    image_path = os.path.abspath(image_path)
    image_name = os.path.basename(image_path)
    
    console.print(f"[bold]Extracting EXIF data from: [cyan]{image_name}[/cyan][/bold]")
    
    # Determine the method to use
    if method == "auto":
        # Try exiftool first, fall back to Python
        if is_exiftool_installed():
            method = "exiftool"
        else:
            method = "python"
            console.print("[yellow]ExifTool not found, using Python-based extraction...[/yellow]")
    
    # Extract EXIF data with the chosen method
    if method == "exiftool" and is_exiftool_installed():
        exif_data = extract_with_exiftool(image_path)
    else:
        exif_data = extract_with_python(image_path)
    
    # Display the results
    display_exif_results(exif_data, image_name)
    
    # Save if requested
    if save and exif_data:
        if format == "json":
            export_utils.save_to_json(exif_data, "exif", image_name)
        else:
            # Flatten nested dictionaries for CSV
            flat_data = {}
            for category, values in exif_data.items():
                if isinstance(values, dict):
                    for key, value in values.items():
                        flat_data[f"{category}_{key}"] = value
                else:
                    flat_data[category] = values
            
            export_utils.save_to_csv(flat_data, "exif", image_name)


@image_commands.command(name="reverse")
@click.argument("image_path", type=click.Path(exists=True))
@click.option("--engine", "-e", 
              type=click.Choice(["google", "tineye", "yandex", "bing", "all"]), 
              default="google", help="Search engine to use")
def reverse_image_search(image_path, engine):
    """
    Open a reverse image search in the default browser.
    
    IMAGE_PATH: Path to the image file.
    """
    image_path = os.path.abspath(image_path)
    image_name = os.path.basename(image_path)
    
    console.print(f"[bold]Performing reverse image search for: [cyan]{image_name}[/cyan][/bold]")
    
    # Check if the file is a valid image
    if not is_valid_image(image_path):
        console.print(f"[red]Error: {image_path} is not a valid image file.[/red]")
        return
    
    # Get file size
    file_size = os.path.getsize(image_path) / (1024 * 1024)  # Size in MB
    
    if file_size > 10:
        console.print(f"[yellow]Warning: The image is {file_size:.1f} MB, which may be too large for some search engines.[/yellow]")
    
    # Prepare search URLs
    if engine == "google" or engine == "all":
        console.print("[green]Opening Google Images search...[/green]")
        google_url = f"https://www.google.com/searchbyimage/upload"
        webbrowser.open(google_url)
        console.print("[yellow]Please upload the image manually in the opened browser window.[/yellow]")
    
    if engine == "tineye" or engine == "all":
        console.print("[green]Opening TinEye search...[/green]")
        tineye_url = "https://tineye.com/"
        webbrowser.open(tineye_url)
        console.print("[yellow]Please upload the image manually in the opened browser window.[/yellow]")
    
    if engine == "yandex" or engine == "all":
        console.print("[green]Opening Yandex Images search...[/green]")
        yandex_url = "https://yandex.com/images/search?rpt=imageview&format=json&url="
        webbrowser.open(yandex_url)
        console.print("[yellow]Please upload the image manually in the opened browser window.[/yellow]")
    
    if engine == "bing" or engine == "all":
        console.print("[green]Opening Bing Visual Search...[/green]")
        bing_url = "https://www.bing.com/images/discover?FORM=ILPMFT"
        webbrowser.open(bing_url)
        console.print("[yellow]Please upload the image manually in the opened browser window.[/yellow]")
    
    console.print("\n[bold]Note:[/bold] Due to search engine restrictions, automatic uploads are not possible.")
    console.print("Please upload the image manually in the browser window(s) that opened.")


def is_exiftool_installed():
    """Check if ExifTool is installed."""
    try:
        result = subprocess.run(
            ["exiftool", "-ver"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def extract_with_exiftool(image_path):
    """Extract EXIF data using ExifTool."""
    with console.status(f"Extracting EXIF data with ExifTool..."):
        try:
            # Run ExifTool with JSON output
            process = subprocess.run(
                ["exiftool", "-j", "-a", "-u", "-g1", image_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=get_setting("timeout")
            )
            
            if process.returncode != 0:
                console.print(f"[red]Error running ExifTool: {process.stderr}[/red]")
                return None
            
            # Parse the JSON output
            exif_json = json.loads(process.stdout)
            
            if exif_json and len(exif_json) > 0:
                # ExifTool returns an array with one item
                return exif_json[0]
            else:
                console.print("[yellow]No EXIF data found in the image.[/yellow]")
                return {}
                
        except Exception as e:
            console.print(f"[red]Error with ExifTool: {e}[/red]")
            return None


def extract_with_python(image_path):
    """Extract EXIF data using Python libraries."""
    exif_data = {}
    
    with console.status(f"Extracting EXIF data with Python..."):
        try:
            # Extract basic image information with PIL
            try:
                with Image.open(image_path) as img:
                    exif_data["Image"] = {
                        "Format": img.format,
                        "Size": f"{img.width}x{img.height}",
                        "Mode": img.mode
                    }
                    
                    # Get more data if it's available
                    if hasattr(img, "_getexif") and img._getexif():
                        pil_exif = img._getexif()
                        
                        # Map common EXIF tags to readable names
                        exif_tags = {
                            271: "Make",
                            272: "Model",
                            306: "DateTime",
                            36867: "DateTimeOriginal",
                            33432: "Copyright",
                            34853: "GPSInfo"
                        }
                        
                        for tag_id, value in pil_exif.items():
                            if tag_id in exif_tags:
                                if tag_id == 34853:  # GPSInfo
                                    exif_data["GPS"] = process_gps_info(value)
                                else:
                                    tag_name = exif_tags[tag_id]
                                    if "DateTime" in tag_name:
                                        exif_data["EXIF"] = exif_data.get("EXIF", {})
                                        exif_data["EXIF"][tag_name] = value
                                    else:
                                        exif_data["Image"][tag_name] = value
            except Exception as e:
                console.print(f"[yellow]Could not extract basic image info: {e}[/yellow]")
            
            # Use exifread for more detailed EXIF extraction
            try:
                with open(image_path, 'rb') as f:
                    tags = exifread.process_file(f, details=True)
                    
                    # Group tags by category
                    for tag, value in tags.items():
                        # Skip MakerNote and large binary data
                        if "MakerNote" in tag or isinstance(value.values, bytes) and len(value.values) > 100:
                            continue
                        
                        # Determine category from tag name
                        if tag.startswith("Image "):
                            category = "Image"
                            tag_name = tag.replace("Image ", "")
                        elif tag.startswith("EXIF "):
                            category = "EXIF"
                            tag_name = tag.replace("EXIF ", "")
                        elif tag.startswith("GPS "):
                            category = "GPS"
                            tag_name = tag.replace("GPS ", "")
                        else:
                            category = "Other"
                            tag_name = tag
                        
                        # Create category if it doesn't exist
                        if category not in exif_data:
                            exif_data[category] = {}
                        
                        # Store the value
                        exif_data[category][tag_name] = str(value)
            except Exception as e:
                console.print(f"[yellow]Could not extract detailed EXIF data: {e}[/yellow]")
            
            return exif_data
                
        except Exception as e:
            console.print(f"[red]Error extracting EXIF data: {e}[/red]")
            return None


def process_gps_info(gps_info):
    """Process GPS information from EXIF data."""
    gps_data = {}
    
    # GPS reference direction tags
    ref_tags = {
        1: 'GPSLatitudeRef',
        3: 'GPSLongitudeRef',
        5: 'GPSAltitudeRef',
    }
    
    # GPS value tags
    value_tags = {
        2: 'GPSLatitude',
        4: 'GPSLongitude',
        6: 'GPSAltitude',
        7: 'GPSTimeStamp',
        29: 'GPSDateStamp'
    }
    
    # Extract reference values
    for key, tag in ref_tags.items():
        if key in gps_info:
            gps_data[tag] = gps_info[key]
    
    # Extract data values
    for key, tag in value_tags.items():
        if key in gps_info:
            gps_data[tag] = gps_info[key]
    
    # Calculate latitude and longitude in decimal degrees
    try:
        if 'GPSLatitude' in gps_data and 'GPSLatitudeRef' in gps_data:
            lat = _convert_to_degrees(gps_data['GPSLatitude'])
            if gps_data['GPSLatitudeRef'] == 'S':
                lat = -lat
            gps_data['Latitude'] = lat
        
        if 'GPSLongitude' in gps_data and 'GPSLongitudeRef' in gps_data:
            lon = _convert_to_degrees(gps_data['GPSLongitude'])
            if gps_data['GPSLongitudeRef'] == 'W':
                lon = -lon
            gps_data['Longitude'] = lon
        
        # Add Google Maps URL if both latitude and longitude are available
        if 'Latitude' in gps_data and 'Longitude' in gps_data:
            lat = gps_data['Latitude']
            lon = gps_data['Longitude']
            gps_data['GoogleMapsURL'] = f"https://maps.google.com/maps?q={lat},{lon}"
    except:
        pass
    
    return gps_data


def _convert_to_degrees(value):
    """Helper function to convert GPS coordinates from EXIF format to decimal degrees."""
    d = float(value[0])
    m = float(value[1])
    s = float(value[2])
    return d + (m / 60.0) + (s / 3600.0)


def is_valid_image(image_path):
    """Check if a file is a valid image."""
    try:
        with Image.open(image_path) as img:
            img.verify()
        return True
    except:
        return False


def display_exif_results(exif_data, image_name):
    """Display EXIF data in an organized way."""
    if not exif_data:
        console.print(f"[yellow]No EXIF data found in image: [bold]{image_name}[/bold][/yellow]")
        return
    
    # Define categories to display and their order
    categories = [
        "Image", "EXIF", "GPS", "Composite", "File", "XMP"
    ]
    
    # First display image basic info
    if "Image" in exif_data:
        image_panel = Panel(
            "\n".join([f"[cyan]{k}:[/cyan] {v}" for k, v in exif_data["Image"].items() if k not in ["SourceFile", "Directory", "FileName"]]),
            title=f"Image Information: [bold]{image_name}[/bold]",
            border_style="blue"
        )
        console.print(image_panel)
    
    # Display GPS information if available
    if "GPS" in exif_data and "Latitude" in exif_data["GPS"] and "Longitude" in exif_data["GPS"]:
        lat = exif_data["GPS"]["Latitude"]
        lon = exif_data["GPS"]["Longitude"]
        
        gps_panel = Panel(
            f"[cyan]Latitude:[/cyan] {lat}\n"
            f"[cyan]Longitude:[/cyan] {lon}\n"
            f"[cyan]Google Maps:[/cyan] https://maps.google.com/maps?q={lat},{lon}",
            title="GPS Location",
            border_style="green"
        )
        console.print(gps_panel)
    
    # Display other EXIF categories in tables
    for category in categories:
        if category in exif_data and category not in ["Image", "GPS"] and exif_data[category]:
            table = Table(title=f"{category} Data")
            
            table.add_column("Tag", style="cyan")
            table.add_column("Value", style="green")
            
            for tag, value in exif_data[category].items():
                # Skip some less useful fields to save space
                if tag in ["SourceFile", "Directory", "FileName"] or "Thumbnail" in tag:
                    continue
                
                # Format the value
                if isinstance(value, dict):
                    value = json.dumps(value, indent=2)
                elif isinstance(value, list):
                    value = ", ".join(str(v) for v in value)
                
                table.add_row(tag, str(value))
            
            console.print(table)
    
    # Print warning if sensitive information is found
    sensitive_data = []
    
    if "GPS" in exif_data and ("Latitude" in exif_data["GPS"] or "Longitude" in exif_data["GPS"]):
        sensitive_data.append("GPS location")
    
    if "EXIF" in exif_data and "SerialNumber" in exif_data["EXIF"]:
        sensitive_data.append("camera serial number")
    
    if sensitive_data:
        console.print(f"[bold red]⚠️ Warning: This image contains sensitive information: {', '.join(sensitive_data)}[/bold red]")