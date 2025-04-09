# OSINT CLI Tool

A free, powerful OSINT (Open Source Intelligence) command-line tool that provides comprehensive intelligence gathering capabilities using only free APIs and resources.

## Features

The OSINT CLI Tool offers multiple intelligence gathering capabilities:

### People Search
- Username search across multiple platforms
- Email verification and breach checks
- Phone number lookup and validation

### IP & Geolocation
- IP address lookups with geolocation data
- WHOIS domain information retrieval

### Domain Intelligence
- DNS record checking
- Subdomain discovery
- Port scanning

### Image Analysis
- EXIF data extraction
- Reverse image search facilitator

### Threat Intelligence
- VirusTotal lookups for files, IPs, and domains
- Shodan search for devices and services

### GitHub Intelligence
- User profile analysis
- Repository information gathering
- Code search for sensitive information (GitHub dorks)

### Additional Utilities
- Hash calculation and identification
- MAC address vendor lookup
- URL parsing and analysis
- Random string generation
- Base64 encoding/decoding
- SSL certificate checking

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/osint-cli-tool.git
cd osint-cli-tool
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On Linux/Mac
source venv/bin/activate
```

3. Install the required dependencies:
```bash
pip install -r osint_tool/requirements.txt
```

4. Set up API keys (optional):
```bash
cp osint_tool/.env.example .env
# Edit the .env file with your API keys
```

## Usage

```bash
python -m osint_tool.main [COMMAND] [OPTIONS]
```

### Available Commands

#### People Search
```bash
# Search for a username across platforms
python -m osint_tool.main username JOHNDOE

# Check an email address
python -m osint_tool.main email user@example.com

# Look up a phone number
python -m osint_tool.main phone +1234567890
```

#### IP & Geolocation
```bash
# Look up information about an IP address
python -m osint_tool.main ip lookup 8.8.8.8

# Perform a WHOIS lookup on an IP or domain
python -m osint_tool.main ip whois example.com
```

#### Domain Intelligence
```bash
# Check DNS records
python -m osint_tool.main domain check-dns example.com

# Find subdomains
python -m osint_tool.main domain find-subdomains example.com

# Scan ports
python -m osint_tool.main domain scan-ports example.com
```

#### Image Analysis
```bash
# Extract EXIF data
python -m osint_tool.main image exif /path/to/image.jpg

# Perform reverse image search
python -m osint_tool.main image reverse /path/to/image.jpg
```

#### Threat Intelligence
```bash
# Check a file, domain, or IP on VirusTotal
python -m osint_tool.main threat check-virustotal example.com

# Search Shodan for information
python -m osint_tool.main threat check-shodan 8.8.8.8
```

#### GitHub Intelligence
```bash
# Analyze GitHub user profile
python -m osint_tool.main github user USERNAME --repos --orgs

# Get repository information
python -m osint_tool.main github repo USERNAME/REPOSITORY --contributors --commits

# Search GitHub for sensitive information
python -m osint_tool.main github dork "password"
```

#### Utilities
```bash
# Calculate hash of a string
python -m osint_tool.main utils hash "text to hash"

# Check a MAC address vendor
python -m osint_tool.main utils mac 00:11:22:33:44:55

# Analyze a URL
python -m osint_tool.main utils url https://example.com/path?param=value

# Generate random strings
python -m osint_tool.main utils random --length 16 --type password

# Encode/decode Base64
python -m osint_tool.main utils base64 "hello world"
python -m osint_tool.main utils base64 "aGVsbG8gd29ybGQ=" --decode

# Check SSL certificate
python -m osint_tool.main utils cert example.com
```

### Global Options

Most commands support these common options:
- `--save` or `-s`: Save results to a file
- `--format` or `-f`: Output format (json or csv)

## API Keys

While the tool works without API keys, adding them enhances its capabilities. The following services can be configured:

- VirusTotal
- Shodan
- EmailRep
- HaveIBeenPwned
- IPinfo
- GitHub

Add your API keys to the `.env` file.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and research purposes only. Users are responsible for complying with applicable laws and regulations when using this tool. The authors assume no liability for misuse or for any damages resulting from the use of this tool. 