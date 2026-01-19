# Homograph Domain Analyzer

A comprehensive Python tool for detecting and analyzing homograph domain variants that could be used for phishing, impersonation, or other fraudulent activities.

## Features

- **Multiple Homograph Techniques**: 16+ transformation techniques including Unicode homoglyphs, typosquatting, IDN attacks, and more
- **DNS Resolution**: Verify if domains are actually registered and resolve to IP addresses
- **WHOIS Analysis**: Retrieve domain registration data including creation date, registrar, and expiration
- **Age-Based Risk Classification**: Classify domains based on registration age with configurable trust thresholds
- **Concurrent Processing**: Multi-threaded analysis for fast scanning of large variant sets
- **Multiple Output Formats**: JSON, CSV, and HTML report generation
- **Batch Processing**: Analyze multiple target domains from a file
- **Extensible**: Easy to add custom transformation rules and TLD lists

## Installation

```bash
# Clone or download the repository
cd homograph_analyzer

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Analyze a Single Domain

```bash
# Basic analysis
python cli.py analyze example.com

# With custom threshold and output
python cli.py analyze example.com -t 1.5 -o report.html -f html

# Verbose output with more variants
python cli.py analyze paypal.com --verbose --max-variants 2000
```

### Batch Analysis

```bash
# Analyze multiple domains from a file
python cli.py batch examples/target_domains.txt --output-dir ./results
```

### List Available Techniques

```bash
python cli.py techniques
```

## Command Line Options

### `analyze` - Analyze a single domain

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --threshold` | Trust threshold in years | 2.0 |
| `-m, --max-variants` | Maximum variants to analyze | 1000 |
| `-o, --output` | Output file path | None |
| `-f, --format` | Output format (json/csv/html) | json |
| `-v, --verbose` | Show detailed output | False |
| `-w, --workers` | Concurrent workers | 10 |
| `--dns-timeout` | DNS query timeout (seconds) | 5.0 |
| `--whois-timeout` | WHOIS query timeout (seconds) | 10.0 |
| `--skip-dns` | Skip DNS resolution | False |
| `--skip-whois` | Skip WHOIS lookups | False |

### `batch` - Analyze multiple domains

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --threshold` | Trust threshold in years | 2.0 |
| `-m, --max-variants` | Max variants per domain | 500 |
| `-o, --output-dir` | Output directory | ./batch_results |
| `-w, --workers` | Concurrent workers | 5 |

## Programmatic Usage

```python
from homograph_domain_analyzer import HomographDomainAnalyzer

# Initialize analyzer
analyzer = HomographDomainAnalyzer(
    trust_threshold_years=2.0,
    max_workers=10
)

# Generate variants only
variants = analyzer.generate_all_variants("example.com")
print(f"Generated {len(variants)} variants")

# Full analysis with DNS and WHOIS
results = analyzer.analyze_domain(
    "example.com",
    check_dns=True,
    check_whois=True,
    max_variants=500
)

# Access results
for variant in results['analyzed_variants']:
    if variant['risk_level'] == 'HIGH':
        print(f"High risk: {variant['domain']} - {variant['technique']}")
```

## Homograph Techniques

The analyzer implements the following transformation techniques:

### Character Substitution
- **Unicode Homoglyphs**: Replaces ASCII with visually similar Unicode (e.g., 'a' → 'а' Cyrillic)
- **ASCII Substitutions**: Common visual substitutions (e.g., 'l' → '1', 'o' → '0')
- **Vowel Swapping**: Replaces vowels with other vowels

### Typosquatting
- **Adjacent Key Swap**: Based on QWERTY keyboard layout
- **Character Transposition**: Swaps adjacent characters
- **Character Omission**: Removes single characters
- **Character Duplication**: Doubles characters
- **Character Insertion**: Inserts extra characters

### Domain Manipulation
- **TLD Variations**: Tests alternative TLDs (.com → .net, .org, .co, etc.)
- **Hyphenation**: Adds hyphens at various positions
- **Dot Insertion**: Creates subdomain-like variants
- **Prefix Addition**: Adds prefixes (www-, secure-, login-, etc.)
- **Suffix Addition**: Adds suffixes (-login, -secure, -official, etc.)

### Advanced Techniques
- **Punycode/IDN**: Internationalized domain name encoding
- **Bit Flipping**: Simulates single-bit errors
- **Word Combination**: Combines with common words

## Risk Classification

Domains are classified based on registration age:

| Risk Level | Criteria | Description |
|------------|----------|-------------|
| **HIGH** | Age < threshold | Recently registered, potentially suspicious |
| **MEDIUM** | threshold ≤ Age < 2×threshold | Relatively new, warrants monitoring |
| **LOW** | Age ≥ 2×threshold | Established domain, lower risk |

The default threshold is 2 years, meaning:
- HIGH: Less than 2 years old
- MEDIUM: 2-4 years old
- LOW: More than 4 years old

## Output Examples

### JSON Output
```json
{
  "target_domain": "example.com",
  "analysis_timestamp": "2025-01-19T12:00:00",
  "trust_threshold_years": 2.0,
  "total_variants_generated": 1500,
  "variants_analyzed": 1000,
  "summary": {
    "registered_domains": 15,
    "high_risk_count": 3,
    "medium_risk_count": 5,
    "low_risk_count": 7
  },
  "analyzed_variants": [...]
}
```

### HTML Report
Generates a styled HTML report with sortable tables, risk badges, and summary statistics.

## Project Structure

```
homograph_analyzer/
├── __init__.py
├── homograph_domain_analyzer.py  # Main analyzer class
├── batch_analyzer.py             # Batch processing
├── cli.py                        # Command-line interface
├── requirements.txt              # Python dependencies
├── README.md                     # Documentation
├── data/
│   ├── unicode_confusables.json  # Unicode character mappings
│   └── tld_list.txt              # Top-level domain list
├── utils/
│   ├── __init__.py
│   ├── dns_utils.py              # DNS resolution utilities
│   └── whois_utils.py            # WHOIS lookup utilities
└── examples/
    └── target_domains.txt        # Example target domains
```

## Extending the Analyzer

### Adding Custom Character Mappings

Edit `data/unicode_confusables.json`:

```json
{
  "a": ["а", "ɑ", "α", "𝐚", "𝑎", "𝒂"],
  "custom_char": ["variant1", "variant2"]
}
```

### Adding Custom TLDs

Edit `data/tld_list.txt` (one TLD per line):

```
com
net
org
custom-tld
```

### Custom Transformation Functions

```python
from homograph_domain_analyzer import HomographDomainAnalyzer

class CustomAnalyzer(HomographDomainAnalyzer):
    def generate_custom_variants(self, domain: str) -> set:
        variants = set()
        # Your custom logic here
        return variants
    
    def generate_all_variants(self, domain: str) -> set:
        variants = super().generate_all_variants(domain)
        variants.update(self.generate_custom_variants(domain))
        return variants
```

## Rate Limiting and Best Practices

- DNS and WHOIS servers may rate limit aggressive queries
- Use reasonable `--max-variants` values (500-1000 recommended)
- Add delays between batch domain analyses
- Consider using your own DNS resolver for large-scale scanning
- Respect WHOIS terms of service

## Legal Disclaimer

This tool is intended for security research, brand protection, and defensive purposes only. Users are responsible for ensuring their use complies with applicable laws and terms of service. Do not use this tool for malicious purposes.

## Dependencies

- `dnspython` - DNS resolution
- `python-whois` - WHOIS lookups
- `tldextract` - Domain parsing
- `idna` - Internationalized domain names
- `requests` - HTTP requests
- `confusable-homoglyphs` - Unicode confusable detection (optional)

## License

MIT License - See LICENSE file for details.
