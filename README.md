# HexaWebScanner

A powerful, parallel web vulnerability scanner that combines OWASP, CVE, and AI-powered scanning capabilities.

## Features

- **Parallel Scanning**: Run multiple vulnerability checks simultaneously for faster results
- **OWASP Top 10 Coverage**: Comprehensive checks for common web vulnerabilities
- **CVE Database Integration**: Check for known vulnerabilities in target systems
- **AI-Powered Analysis**: Zero-day vulnerability detection using Hugging Face AI
- **Real-time Reporting**: Get results as they are discovered
- **Database Storage**: Save scan results for historical analysis

## Installation

1. Clone the repository:
```bash
git clone https://github.com/HexaGuardOfficial/HexaWebScanner.git
cd HexaWebScanner
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file in the project root with:
```
HUGGINGFACE_API_TOKEN=your_token_here  # For AI-powered scanning
```

## Usage

Basic usage:
```bash
python run.py http://example.com
```

### Command Line Arguments

- `target_url`: The URL to scan (required)
  - Example: `http://example.com`
  - Note: URL must include protocol (http:// or https://)

### Output

The scanner provides:
- Real-time progress updates
- Detailed vulnerability findings
- Severity levels for each vulnerability
- Recommendations for fixes
- Results saved to database

## Components

### 1. OWASP Scanner
- SQL Injection detection
- Cross-Site Scripting (XSS) checks
- CSRF vulnerability testing
- Security misconfiguration detection
- And more...

### 2. CVE Scanner
- Database of known vulnerabilities
- Version-based vulnerability checking
- Real-time CVE data updates
- Severity scoring

### 3. ZeroDay AI Scanner
- AI-powered vulnerability detection
- Pattern recognition
- Anomaly detection
- Requires Hugging Face API token

## Database

Scan results are stored in a local database for:
- Historical analysis
- Trend tracking
- Report generation
- Vulnerability tracking

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Security

- This tool is for authorized security testing only
- Do not use against systems you don't own or have permission to test
- Follow all applicable laws and regulations

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please:
1. Check the documentation
2. Search existing issues
3. Create a new issue if needed

## Acknowledgments

- OWASP for vulnerability guidelines
- NVD for CVE data
- Hugging Face for AI capabilities
- All contributors to this project

## Roadmap

- [ ] Add more vulnerability checks
- [ ] Improve AI detection capabilities
- [ ] Add GUI interface
- [ ] Implement API for integration
- [ ] Add more reporting formats 