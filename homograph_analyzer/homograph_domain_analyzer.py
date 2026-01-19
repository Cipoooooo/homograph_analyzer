#!/usr/bin/env python3
"""
Homograph Domain Analyzer
=========================

A comprehensive tool for identifying and analyzing homograph domain variants
that could be used for phishing, typosquatting, or brand impersonation.

Features:
- Multiple homograph transformation techniques
- DNS existence verification
- WHOIS creation date lookup
- Domain age-based trust classification
- Concurrent processing for performance
- Multiple output formats (JSON, CSV, console)

Author: Security Research Tool
License: MIT
"""

import re
import sys
import json
import socket
import argparse
import logging
import csv
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import product
import time

# Third-party imports
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("Warning: python-whois not installed. WHOIS lookups will be disabled.")

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("Warning: dnspython not installed. Using basic socket lookup.")

try:
    from confusable_homoglyphs import confusables
    CONFUSABLES_AVAILABLE = True
except ImportError:
    CONFUSABLES_AVAILABLE = False
    print("Warning: confusable_homoglyphs not installed. Using built-in mappings.")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.panel import Panel
    from rich import print as rprint
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# HOMOGRAPH CHARACTER MAPPINGS
# ============================================================================

# Comprehensive ASCII to Unicode lookalike mappings
HOMOGRAPH_MAPPINGS: Dict[str, List[str]] = {
    # Latin lowercase
    'a': ['а', 'ɑ', 'α', 'ạ', 'ą', 'à', 'á', 'â', 'ã', 'ä', 'å', 'ā', 'ă', 'ǎ', 'ȁ', 'ȃ', 'ả', 'ấ', 'ầ', 'ẩ', 'ẫ', 'ậ', 'ắ', 'ằ', 'ẳ', 'ẵ', 'ặ'],
    'b': ['Ь', 'ƅ', 'Ԁ', 'ḃ', 'ḅ', 'ḇ', 'ƀ'],
    'c': ['с', 'ϲ', 'ċ', 'ç', 'ć', 'ĉ', 'č', 'ƈ', 'ȼ'],
    'd': ['ԁ', 'ɗ', 'ḋ', 'ḍ', 'ḏ', 'ḑ', 'ḓ', 'ď', 'đ'],
    'e': ['е', 'ё', 'ẹ', 'ę', 'è', 'é', 'ê', 'ë', 'ē', 'ĕ', 'ė', 'ě', 'ȅ', 'ȇ', 'ẻ', 'ẽ', 'ế', 'ề', 'ể', 'ễ', 'ệ'],
    'f': ['ƒ', 'ḟ'],
    'g': ['ɡ', 'ġ', 'ģ', 'ĝ', 'ğ', 'ǧ', 'ǵ', 'ḡ'],
    'h': ['һ', 'ḣ', 'ḥ', 'ḧ', 'ḩ', 'ḫ', 'ĥ', 'ȟ', 'ħ'],
    'i': ['і', 'ı', 'ɩ', 'ì', 'í', 'î', 'ï', 'ĩ', 'ī', 'ĭ', 'į', 'ǐ', 'ȉ', 'ȋ', 'ỉ', 'ị'],
    'j': ['ј', 'ĵ', 'ǰ'],
    'k': ['κ', 'ḱ', 'ḳ', 'ḵ', 'ķ', 'ĸ'],
    'l': ['ӏ', 'ḷ', 'ḹ', 'ḻ', 'ḽ', 'ĺ', 'ļ', 'ľ', 'ŀ', 'ł', '1', '|'],
    'm': ['ṁ', 'ṃ', 'ɱ', 'rn'],
    'n': ['ո', 'ṅ', 'ṇ', 'ṉ', 'ṋ', 'ń', 'ņ', 'ň', 'ŉ', 'ɲ', 'ƞ'],
    'o': ['о', 'ο', 'σ', '0', 'ọ', 'ø', 'ò', 'ó', 'ô', 'õ', 'ö', 'ō', 'ŏ', 'ő', 'ơ', 'ǒ', 'ǫ', 'ǭ', 'ȍ', 'ȏ', 'ȯ', 'ȱ', 'ỏ', 'ố', 'ồ', 'ổ', 'ỗ', 'ộ', 'ớ', 'ờ', 'ở', 'ỡ', 'ợ'],
    'p': ['р', 'ρ', 'ṕ', 'ṗ', 'ƥ'],
    'q': ['ԛ', 'ɋ'],
    'r': ['г', 'ṙ', 'ṛ', 'ṝ', 'ṟ', 'ŕ', 'ŗ', 'ř', 'ȑ', 'ȓ'],
    's': ['ѕ', 'ṡ', 'ṣ', 'ṥ', 'ṧ', 'ṩ', 'ś', 'ŝ', 'ş', 'š', 'ș', '5', '$'],
    't': ['τ', 'ṫ', 'ṭ', 'ṯ', 'ṱ', 'ţ', 'ť', 'ŧ', 'ț', '7'],
    'u': ['υ', 'ս', 'ụ', 'ù', 'ú', 'û', 'ü', 'ũ', 'ū', 'ŭ', 'ů', 'ű', 'ų', 'ư', 'ǔ', 'ǖ', 'ǘ', 'ǚ', 'ǜ', 'ȕ', 'ȗ', 'ủ', 'ứ', 'ừ', 'ử', 'ữ', 'ự'],
    'v': ['ν', 'ѵ', 'ṽ', 'ṿ'],
    'w': ['ԝ', 'ẁ', 'ẃ', 'ẅ', 'ẇ', 'ẉ', 'ŵ', 'vv'],
    'x': ['х', 'χ', 'ẋ', 'ẍ'],
    'y': ['у', 'γ', 'ỳ', 'ý', 'ŷ', 'ÿ', 'ỹ', 'ȳ', 'ẏ', 'ỵ', 'ỷ'],
    'z': ['ᴢ', 'ź', 'ż', 'ž', 'ẑ', 'ẓ', 'ẕ', 'ƶ'],
    
    # Latin uppercase (for case variations)
    'A': ['А', 'Α', 'Ạ', 'Ą', 'À', 'Á', 'Â', 'Ã', 'Ä', 'Å', 'Ā', 'Ă', 'Ǎ'],
    'B': ['В', 'Β', 'Ḃ', 'Ḅ', 'Ḇ', 'Ɓ'],
    'C': ['С', 'Ϲ', 'Ċ', 'Ç', 'Ć', 'Ĉ', 'Č'],
    'E': ['Е', 'Ε', 'Ẹ', 'Ę', 'È', 'É', 'Ê', 'Ë', 'Ē', 'Ĕ', 'Ė', 'Ě'],
    'H': ['Н', 'Η', 'Ḣ', 'Ḥ', 'Ḧ', 'Ḩ', 'Ḫ', 'Ĥ'],
    'I': ['І', 'Ι', 'Ì', 'Í', 'Î', 'Ï', 'Ĩ', 'Ī', 'Ĭ', 'İ', 'Į', '1', 'l', '|'],
    'K': ['Κ', 'К', 'Ḱ', 'Ḳ', 'Ḵ', 'Ķ'],
    'M': ['Μ', 'М', 'Ṁ', 'Ṃ'],
    'N': ['Ν', 'Ṅ', 'Ṇ', 'Ṉ', 'Ṋ', 'Ń', 'Ņ', 'Ň'],
    'O': ['О', 'Ο', '0', 'Ọ', 'Ø', 'Ò', 'Ó', 'Ô', 'Õ', 'Ö', 'Ō', 'Ŏ', 'Ő', 'Ơ'],
    'P': ['Р', 'Ρ', 'Ṕ', 'Ṗ'],
    'S': ['Ѕ', 'Ṡ', 'Ṣ', 'Ṥ', 'Ṧ', 'Ṩ', 'Ś', 'Ŝ', 'Ş', 'Š', '5', '$'],
    'T': ['Τ', 'Т', 'Ṫ', 'Ṭ', 'Ṯ', 'Ṱ', 'Ţ', 'Ť', 'Ŧ', '7'],
    'X': ['Χ', 'Х', 'Ẋ', 'Ẍ'],
    'Y': ['Υ', 'У', 'Ỳ', 'Ý', 'Ŷ', 'Ÿ', 'Ỹ', 'Ȳ', 'Ẏ'],
    'Z': ['Ζ', 'Ź', 'Ż', 'Ž', 'Ẑ', 'Ẓ', 'Ẕ'],
}

# Number/letter substitutions (leetspeak)
LEETSPEAK_MAPPINGS: Dict[str, List[str]] = {
    'a': ['4', '@'],
    'b': ['8'],
    'e': ['3'],
    'g': ['9', '6'],
    'i': ['1', '!', '|'],
    'l': ['1', '|'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7', '+'],
    'z': ['2'],
}

# Common keyboard typos (QWERTY layout)
KEYBOARD_TYPOS: Dict[str, List[str]] = {
    'a': ['q', 'w', 's', 'z'],
    'b': ['v', 'g', 'h', 'n'],
    'c': ['x', 'd', 'f', 'v'],
    'd': ['s', 'e', 'r', 'f', 'c', 'x'],
    'e': ['w', 's', 'd', 'r'],
    'f': ['d', 'r', 't', 'g', 'v', 'c'],
    'g': ['f', 't', 'y', 'h', 'b', 'v'],
    'h': ['g', 'y', 'u', 'j', 'n', 'b'],
    'i': ['u', 'j', 'k', 'o'],
    'j': ['h', 'u', 'i', 'k', 'm', 'n'],
    'k': ['j', 'i', 'o', 'l', 'm'],
    'l': ['k', 'o', 'p'],
    'm': ['n', 'j', 'k'],
    'n': ['b', 'h', 'j', 'm'],
    'o': ['i', 'k', 'l', 'p'],
    'p': ['o', 'l'],
    'q': ['w', 'a'],
    'r': ['e', 'd', 'f', 't'],
    's': ['a', 'w', 'e', 'd', 'x', 'z'],
    't': ['r', 'f', 'g', 'y'],
    'u': ['y', 'h', 'j', 'i'],
    'v': ['c', 'f', 'g', 'b'],
    'w': ['q', 'a', 's', 'e'],
    'x': ['z', 's', 'd', 'c'],
    'y': ['t', 'g', 'h', 'u'],
    'z': ['a', 's', 'x'],
}

# Common phonetic substitutions
PHONETIC_SUBSTITUTIONS: Dict[str, List[str]] = {
    'f': ['ph'],
    'ph': ['f'],
    'ck': ['k', 'c'],
    'k': ['c', 'ck'],
    'c': ['k', 's'],
    's': ['c', 'z'],
    'z': ['s'],
    'x': ['ks', 'cks'],
    'w': ['vv', 'uu'],
    'i': ['y', 'ee'],
    'y': ['i', 'ie'],
    'oo': ['u'],
    'u': ['oo'],
}

# Common word substitutions
WORD_SUBSTITUTIONS: Dict[str, List[str]] = {
    'and': ['n', '-', '&'],
    'for': ['4', 'four'],
    'to': ['2', 'too', 'two'],
    'you': ['u', 'yu'],
    'are': ['r'],
    'be': ['b'],
    'see': ['c'],
    'one': ['1', 'won'],
    'two': ['2', 'to', 'too'],
    'four': ['4', 'for'],
    'ate': ['8'],
    'at': ['@'],
}

# Common TLDs for variation
ALTERNATIVE_TLDS: List[str] = [
    # Generic TLDs
    'com', 'net', 'org', 'info', 'biz', 'co', 'io', 'app', 'dev', 'ai',
    'xyz', 'online', 'site', 'website', 'tech', 'store', 'shop', 'club',
    # Country TLDs commonly used
    'uk', 'us', 'de', 'fr', 'it', 'es', 'nl', 'ru', 'cn', 'jp', 'kr',
    'in', 'au', 'ca', 'br', 'mx', 'pl', 'cz', 'ch', 'at', 'be', 'se',
    # Combo TLDs
    'co.uk', 'com.au', 'co.in', 'co.jp', 'com.br', 'co.nz', 'com.mx',
    # New gTLDs often used in phishing
    'top', 'work', 'click', 'link', 'live', 'world', 'today', 'email',
    'best', 'win', 'vip', 'ltd', 'group', 'company', 'solutions',
]

# Prefixes and suffixes commonly used in phishing
PHISHING_PREFIXES: List[str] = [
    'www-', 'www.', 'login-', 'signin-', 'secure-', 'account-', 'my-',
    'portal-', 'support-', 'help-', 'auth-', 'verify-', 'update-',
    'service-', 'online-', 'web-', 'mobile-', 'app-', 'mail-', 'admin-',
]

PHISHING_SUFFIXES: List[str] = [
    '-login', '-signin', '-secure', '-account', '-portal', '-support',
    '-help', '-auth', '-verify', '-update', '-service', '-online',
    '-web', '-mobile', '-app', '-mail', '-admin', '-official', '-real',
    '-security', '-center', '-team', '-group', '-inc', '-corp', '-ltd',
]


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class DomainVariant:
    """Represents a generated domain variant with analysis results."""
    original_domain: str
    variant_domain: str
    technique: str
    technique_detail: str = ""
    is_registered: bool = False
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    whois_data: Dict[str, Any] = field(default_factory=dict)
    creation_date: Optional[datetime] = None
    registrar: Optional[str] = None
    domain_age_days: Optional[int] = None
    trust_level: str = "unknown"  # low, medium, high, unknown
    risk_score: int = 0  # 0-100
    error: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        if data['creation_date']:
            data['creation_date'] = data['creation_date'].isoformat()
        return data


@dataclass
class AnalysisConfig:
    """Configuration for the homograph analysis."""
    target_domain: str
    trust_threshold_days: int = 730  # 2 years default
    max_variants: int = 1000
    check_dns: bool = True
    check_whois: bool = True
    threads: int = 10
    timeout: int = 5
    include_unregistered: bool = False
    techniques: List[str] = field(default_factory=lambda: ['all'])
    output_format: str = 'console'  # console, json, csv
    output_file: Optional[str] = None
    verbose: bool = False


# ============================================================================
# DOMAIN VARIANT GENERATOR
# ============================================================================

class HomographGenerator:
    """Generates homograph domain variants using multiple techniques."""
    
    def __init__(self, config: AnalysisConfig):
        self.config = config
        self.domain_name, self.tld = self._parse_domain(config.target_domain)
        self.generated_variants: Set[str] = set()
        
    def _parse_domain(self, domain: str) -> Tuple[str, str]:
        """Parse domain into name and TLD."""
        domain = domain.lower().strip()
        
        # Remove protocol if present
        if '://' in domain:
            domain = domain.split('://')[1]
        
        # Remove path if present
        if '/' in domain:
            domain = domain.split('/')[0]
            
        # Remove www if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        if TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(domain)
            return extracted.domain, extracted.suffix
        else:
            # Simple fallback
            parts = domain.rsplit('.', 1)
            if len(parts) == 2:
                return parts[0], parts[1]
            return domain, 'com'
    
    def _add_variant(self, name: str, tld: str, technique: str, detail: str = "") -> Optional[DomainVariant]:
        """Add a variant if it's unique and valid."""
        # Clean and validate
        name = name.lower().strip()
        tld = tld.lower().strip()
        
        if not name or not tld:
            return None
            
        full_domain = f"{name}.{tld}"
        
        # Skip if same as original
        if full_domain == f"{self.domain_name}.{self.tld}":
            return None
            
        # Skip if already generated
        if full_domain in self.generated_variants:
            return None
            
        # Skip if exceeds max variants
        if len(self.generated_variants) >= self.config.max_variants:
            return None
            
        self.generated_variants.add(full_domain)
        
        return DomainVariant(
            original_domain=f"{self.domain_name}.{self.tld}",
            variant_domain=full_domain,
            technique=technique,
            technique_detail=detail
        )
    
    def generate_all(self) -> List[DomainVariant]:
        """Generate all domain variants based on configured techniques."""
        variants = []
        techniques = self.config.techniques
        
        if 'all' in techniques:
            techniques = [
                'homograph', 'leetspeak', 'typo', 'phonetic',
                'repetition', 'omission', 'insertion', 'transposition',
                'hyphenation', 'tld', 'prefix', 'suffix', 'vowel_swap',
                'double_char', 'bitsquatting', 'subdomain'
            ]
        
        for technique in techniques:
            method = getattr(self, f'_generate_{technique}', None)
            if method:
                try:
                    results = method()
                    variants.extend([v for v in results if v is not None])
                except Exception as e:
                    logger.warning(f"Error in technique {technique}: {e}")
                    
        logger.info(f"Generated {len(variants)} unique domain variants")
        return variants
    
    def _generate_homograph(self) -> List[DomainVariant]:
        """Generate Unicode homograph variants."""
        variants = []
        name = self.domain_name
        
        # Single character substitutions
        for i, char in enumerate(name):
            if char in HOMOGRAPH_MAPPINGS:
                for replacement in HOMOGRAPH_MAPPINGS[char][:3]:  # Limit per char
                    new_name = name[:i] + replacement + name[i+1:]
                    variant = self._add_variant(
                        new_name, self.tld, 'homograph',
                        f"Replaced '{char}' with '{replacement}'"
                    )
                    if variant:
                        variants.append(variant)
        
        # Try confusable_homoglyphs library if available
        if CONFUSABLES_AVAILABLE:
            try:
                for i, char in enumerate(name):
                    conf = confusables.is_confusable(char, greedy=True)
                    if conf:
                        for item in conf[:2]:
                            for homoglyph in item.get('homoglyphs', [])[:2]:
                                repl = homoglyph.get('c', '')
                                if repl and repl != char:
                                    new_name = name[:i] + repl + name[i+1:]
                                    variant = self._add_variant(
                                        new_name, self.tld, 'homograph',
                                        f"Confusable: '{char}' -> '{repl}'"
                                    )
                                    if variant:
                                        variants.append(variant)
            except Exception as e:
                logger.debug(f"Confusables error: {e}")
        
        return variants
    
    def _generate_leetspeak(self) -> List[DomainVariant]:
        """Generate leetspeak variants."""
        variants = []
        name = self.domain_name
        
        for i, char in enumerate(name):
            if char in LEETSPEAK_MAPPINGS:
                for replacement in LEETSPEAK_MAPPINGS[char]:
                    new_name = name[:i] + replacement + name[i+1:]
                    variant = self._add_variant(
                        new_name, self.tld, 'leetspeak',
                        f"Replaced '{char}' with '{replacement}'"
                    )
                    if variant:
                        variants.append(variant)
        
        return variants
    
    def _generate_typo(self) -> List[DomainVariant]:
        """Generate keyboard typo variants."""
        variants = []
        name = self.domain_name
        
        for i, char in enumerate(name):
            if char in KEYBOARD_TYPOS:
                for replacement in KEYBOARD_TYPOS[char][:2]:  # Limit
                    new_name = name[:i] + replacement + name[i+1:]
                    variant = self._add_variant(
                        new_name, self.tld, 'typo',
                        f"Keyboard typo: '{char}' -> '{replacement}'"
                    )
                    if variant:
                        variants.append(variant)
        
        return variants
    
    def _generate_phonetic(self) -> List[DomainVariant]:
        """Generate phonetic substitution variants."""
        variants = []
        name = self.domain_name
        
        for pattern, replacements in PHONETIC_SUBSTITUTIONS.items():
            if pattern in name:
                for replacement in replacements:
                    new_name = name.replace(pattern, replacement, 1)
                    variant = self._add_variant(
                        new_name, self.tld, 'phonetic',
                        f"Phonetic: '{pattern}' -> '{replacement}'"
                    )
                    if variant:
                        variants.append(variant)
        
        return variants
    
    def _generate_repetition(self) -> List[DomainVariant]:
        """Generate character repetition variants."""
        variants = []
        name = self.domain_name
        
        for i, char in enumerate(name):
            if char.isalpha():
                new_name = name[:i] + char + char + name[i+1:]
                variant = self._add_variant(
                    new_name, self.tld, 'repetition',
                    f"Doubled '{char}' at position {i}"
                )
                if variant:
                    variants.append(variant)
        
        return variants
    
    def _generate_omission(self) -> List[DomainVariant]:
        """Generate character omission variants."""
        variants = []
        name = self.domain_name
        
        for i in range(len(name)):
            new_name = name[:i] + name[i+1:]
            if new_name:  # Must have at least 1 char
                variant = self._add_variant(
                    new_name, self.tld, 'omission',
                    f"Omitted '{name[i]}' at position {i}"
                )
                if variant:
                    variants.append(variant)
        
        return variants
    
    def _generate_insertion(self) -> List[DomainVariant]:
        """Generate character insertion variants."""
        variants = []
        name = self.domain_name
        common_chars = 'aeiourstnl'
        
        for i in range(len(name) + 1):
            for char in common_chars:
                new_name = name[:i] + char + name[i:]
                variant = self._add_variant(
                    new_name, self.tld, 'insertion',
                    f"Inserted '{char}' at position {i}"
                )
                if variant:
                    variants.append(variant)
        
        return variants
    
    def _generate_transposition(self) -> List[DomainVariant]:
        """Generate adjacent character transposition variants."""
        variants = []
        name = self.domain_name
        
        for i in range(len(name) - 1):
            new_name = name[:i] + name[i+1] + name[i] + name[i+2:]
            variant = self._add_variant(
                new_name, self.tld, 'transposition',
                f"Swapped '{name[i]}' and '{name[i+1]}'"
            )
            if variant:
                variants.append(variant)
        
        return variants
    
    def _generate_hyphenation(self) -> List[DomainVariant]:
        """Generate hyphenation variants."""
        variants = []
        name = self.domain_name
        
        # Add hyphens between characters
        for i in range(1, len(name)):
            new_name = name[:i] + '-' + name[i:]
            variant = self._add_variant(
                new_name, self.tld, 'hyphenation',
                f"Hyphen inserted at position {i}"
            )
            if variant:
                variants.append(variant)
        
        # Remove existing hyphens
        if '-' in name:
            new_name = name.replace('-', '')
            variant = self._add_variant(
                new_name, self.tld, 'hyphenation',
                "Removed hyphens"
            )
            if variant:
                variants.append(variant)
        
        return variants
    
    def _generate_tld(self) -> List[DomainVariant]:
        """Generate alternative TLD variants."""
        variants = []
        
        for tld in ALTERNATIVE_TLDS:
            if tld != self.tld:
                variant = self._add_variant(
                    self.domain_name, tld, 'tld_swap',
                    f"Changed TLD from '.{self.tld}' to '.{tld}'"
                )
                if variant:
                    variants.append(variant)
        
        return variants
    
    def _generate_prefix(self) -> List[DomainVariant]:
        """Generate prefix variants."""
        variants = []
        
        for prefix in PHISHING_PREFIXES:
            clean_prefix = prefix.rstrip('-.')
            new_name = clean_prefix + self.domain_name
            variant = self._add_variant(
                new_name, self.tld, 'prefix',
                f"Added prefix '{prefix}'"
            )
            if variant:
                variants.append(variant)
        
        return variants
    
    def _generate_suffix(self) -> List[DomainVariant]:
        """Generate suffix variants."""
        variants = []
        
        for suffix in PHISHING_SUFFIXES:
            clean_suffix = suffix.lstrip('-')
            new_name = self.domain_name + clean_suffix
            variant = self._add_variant(
                new_name, self.tld, 'suffix',
                f"Added suffix '{suffix}'"
            )
            if variant:
                variants.append(variant)
        
        return variants
    
    def _generate_vowel_swap(self) -> List[DomainVariant]:
        """Generate vowel swap variants."""
        variants = []
        name = self.domain_name
        vowels = 'aeiou'
        
        for i, char in enumerate(name):
            if char in vowels:
                for vowel in vowels:
                    if vowel != char:
                        new_name = name[:i] + vowel + name[i+1:]
                        variant = self._add_variant(
                            new_name, self.tld, 'vowel_swap',
                            f"Swapped '{char}' with '{vowel}'"
                        )
                        if variant:
                            variants.append(variant)
        
        return variants
    
    def _generate_double_char(self) -> List[DomainVariant]:
        """Handle double character variations."""
        variants = []
        name = self.domain_name
        
        # Find double characters and reduce them
        i = 0
        while i < len(name) - 1:
            if name[i] == name[i+1]:
                new_name = name[:i] + name[i+1:]
                variant = self._add_variant(
                    new_name, self.tld, 'double_char',
                    f"Reduced double '{name[i]}'"
                )
                if variant:
                    variants.append(variant)
            i += 1
        
        return variants
    
    def _generate_bitsquatting(self) -> List[DomainVariant]:
        """Generate bitsquatting variants (single bit flips)."""
        variants = []
        name = self.domain_name
        
        for i, char in enumerate(name):
            ascii_val = ord(char)
            for bit in range(8):
                flipped = ascii_val ^ (1 << bit)
                if 97 <= flipped <= 122:  # lowercase letters
                    new_char = chr(flipped)
                    if new_char != char:
                        new_name = name[:i] + new_char + name[i+1:]
                        variant = self._add_variant(
                            new_name, self.tld, 'bitsquatting',
                            f"Bit flip: '{char}' -> '{new_char}'"
                        )
                        if variant:
                            variants.append(variant)
        
        return variants
    
    def _generate_subdomain(self) -> List[DomainVariant]:
        """Generate subdomain impersonation variants."""
        variants = []
        
        # Original as subdomain of different TLD
        subdomains = ['login', 'secure', 'account', 'auth', 'my', 'portal']
        
        for sub in subdomains:
            # e.g., example.login.com
            variant = self._add_variant(
                f"{self.domain_name}.{sub}", 'com', 'subdomain',
                f"Domain as subdomain: {sub}.com"
            )
            if variant:
                variants.append(variant)
        
        return variants


# ============================================================================
# DOMAIN ANALYZER
# ============================================================================

class DomainAnalyzer:
    """Analyzes domain variants for registration status and WHOIS data."""
    
    def __init__(self, config: AnalysisConfig):
        self.config = config
        self.dns_resolver = None
        
        if DNS_AVAILABLE:
            self.dns_resolver = dns.resolver.Resolver()
            self.dns_resolver.timeout = config.timeout
            self.dns_resolver.lifetime = config.timeout
    
    def check_dns(self, domain: str) -> Tuple[bool, Dict[str, List[str]]]:
        """Check if domain resolves via DNS."""
        records = {}
        is_registered = False
        
        if DNS_AVAILABLE and self.dns_resolver:
            for record_type in ['A', 'AAAA', 'MX', 'NS']:
                try:
                    answers = self.dns_resolver.resolve(domain, record_type)
                    records[record_type] = [str(rdata) for rdata in answers]
                    is_registered = True
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers, dns.exception.Timeout):
                    pass
                except Exception as e:
                    logger.debug(f"DNS error for {domain} ({record_type}): {e}")
        else:
            # Fallback to basic socket lookup
            try:
                socket.setdefaulttimeout(self.config.timeout)
                result = socket.gethostbyname(domain)
                records['A'] = [result]
                is_registered = True
            except socket.gaierror:
                pass
            except Exception as e:
                logger.debug(f"Socket error for {domain}: {e}")
        
        return is_registered, records
    
    def get_whois(self, domain: str) -> Tuple[Optional[datetime], Optional[str], Dict]:
        """Get WHOIS data for a domain."""
        creation_date = None
        registrar = None
        whois_data = {}
        
        if not WHOIS_AVAILABLE:
            return None, None, {}
        
        try:
            w = whois.whois(domain)
            whois_data = dict(w) if w else {}
            
            # Handle creation_date (can be list or single value)
            cd = w.creation_date
            if isinstance(cd, list):
                creation_date = cd[0] if cd else None
            else:
                creation_date = cd
            
            # Ensure it's a datetime object
            if creation_date and not isinstance(creation_date, datetime):
                try:
                    creation_date = datetime.strptime(str(creation_date), '%Y-%m-%d')
                except:
                    creation_date = None
            
            registrar = w.registrar
            
        except Exception as e:
            logger.debug(f"WHOIS error for {domain}: {e}")
        
        return creation_date, registrar, whois_data
    
    def calculate_trust_level(self, domain_age_days: Optional[int]) -> Tuple[str, int]:
        """Calculate trust level and risk score based on domain age."""
        if domain_age_days is None:
            return 'unknown', 50
        
        threshold = self.config.trust_threshold_days
        
        if domain_age_days < 30:
            return 'critical', 95
        elif domain_age_days < 90:
            return 'high_risk', 85
        elif domain_age_days < 180:
            return 'suspicious', 70
        elif domain_age_days < 365:
            return 'low_trust', 55
        elif domain_age_days < threshold:
            return 'moderate', 35
        else:
            return 'established', 15
    
    def analyze_variant(self, variant: DomainVariant) -> DomainVariant:
        """Analyze a single domain variant."""
        try:
            # Check DNS
            if self.config.check_dns:
                variant.is_registered, variant.dns_records = self.check_dns(
                    variant.variant_domain
                )
            
            # Only do WHOIS if domain is registered
            if variant.is_registered and self.config.check_whois:
                creation_date, registrar, whois_data = self.get_whois(
                    variant.variant_domain
                )
                variant.creation_date = creation_date
                variant.registrar = registrar
                variant.whois_data = {
                    k: str(v) for k, v in whois_data.items()
                    if k in ['domain_name', 'registrar', 'creation_date', 
                            'expiration_date', 'name_servers', 'org', 'country']
                }
                
                # Calculate domain age
                if creation_date:
                    age_delta = datetime.now() - creation_date
                    variant.domain_age_days = age_delta.days
                
                # Calculate trust level
                variant.trust_level, variant.risk_score = self.calculate_trust_level(
                    variant.domain_age_days
                )
            elif variant.is_registered:
                variant.trust_level = 'unknown'
                variant.risk_score = 50
            else:
                variant.trust_level = 'unregistered'
                variant.risk_score = 0
                
        except Exception as e:
            variant.error = str(e)
            logger.debug(f"Error analyzing {variant.variant_domain}: {e}")
        
        return variant
    
    def analyze_all(self, variants: List[DomainVariant]) -> List[DomainVariant]:
        """Analyze all variants with concurrent processing."""
        results = []
        total = len(variants)
        
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task(
                    f"[cyan]Analyzing {total} domains...", total=total
                )
                
                with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                    futures = {
                        executor.submit(self.analyze_variant, v): v
                        for v in variants
                    }
                    
                    for future in as_completed(futures):
                        result = future.result()
                        results.append(result)
                        progress.advance(task)
                        time.sleep(0.1)  # Rate limiting
        else:
            print(f"Analyzing {total} domains...")
            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                futures = {
                    executor.submit(self.analyze_variant, v): v
                    for v in variants
                }
                
                completed = 0
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)
                    completed += 1
                    if completed % 10 == 0:
                        print(f"  Progress: {completed}/{total}")
                    time.sleep(0.1)
        
        return results


# ============================================================================
# OUTPUT FORMATTERS
# ============================================================================

class OutputFormatter:
    """Formats and outputs analysis results."""
    
    @staticmethod
    def format_console(results: List[DomainVariant], config: AnalysisConfig):
        """Format results for console output."""
        # Filter results
        if not config.include_unregistered:
            results = [r for r in results if r.is_registered]
        
        # Sort by risk score (highest first)
        results.sort(key=lambda x: x.risk_score, reverse=True)
        
        if RICH_AVAILABLE:
            OutputFormatter._rich_console_output(results, config)
        else:
            OutputFormatter._basic_console_output(results, config)
    
    @staticmethod
    def _rich_console_output(results: List[DomainVariant], config: AnalysisConfig):
        """Rich console output with tables."""
        console.print()
        console.print(Panel(
            f"[bold]Homograph Analysis Results for [cyan]{config.target_domain}[/cyan][/bold]\n"
            f"Trust threshold: {config.trust_threshold_days} days ({config.trust_threshold_days // 365} years)",
            title="Analysis Complete"
        ))
        
        # Summary statistics
        registered = [r for r in results if r.is_registered]
        suspicious = [r for r in registered if r.trust_level in 
                     ['critical', 'high_risk', 'suspicious', 'low_trust']]
        
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"  Total variants generated: {len(results) + len([r for r in results if not r.is_registered])}")
        console.print(f"  Registered domains found: [yellow]{len(registered)}[/yellow]")
        console.print(f"  Suspicious/Low-trust domains: [red]{len(suspicious)}[/red]")
        
        if not results:
            console.print("\n[yellow]No registered domains found.[/yellow]")
            return
        
        # Create results table
        table = Table(title="\nDetailed Results", show_header=True, header_style="bold magenta")
        table.add_column("Domain", style="cyan", no_wrap=True)
        table.add_column("Technique", style="dim")
        table.add_column("Age (days)", justify="right")
        table.add_column("Trust Level", justify="center")
        table.add_column("Risk Score", justify="right")
        table.add_column("Registrar", style="dim", max_width=30)
        
        risk_colors = {
            'critical': 'red bold',
            'high_risk': 'red',
            'suspicious': 'yellow',
            'low_trust': 'yellow dim',
            'moderate': 'green dim',
            'established': 'green',
            'unknown': 'dim',
            'unregistered': 'dim'
        }
        
        for result in results[:50]:  # Limit display
            age_str = str(result.domain_age_days) if result.domain_age_days else "N/A"
            risk_style = risk_colors.get(result.trust_level, 'dim')
            
            table.add_row(
                result.variant_domain,
                result.technique,
                age_str,
                f"[{risk_style}]{result.trust_level}[/{risk_style}]",
                f"[{risk_style}]{result.risk_score}[/{risk_style}]",
                result.registrar or "N/A"
            )
        
        console.print(table)
        
        if len(results) > 50:
            console.print(f"\n[dim]... and {len(results) - 50} more results.[/dim]")
    
    @staticmethod
    def _basic_console_output(results: List[DomainVariant], config: AnalysisConfig):
        """Basic console output without rich."""
        print("\n" + "=" * 70)
        print(f"Homograph Analysis Results for {config.target_domain}")
        print(f"Trust threshold: {config.trust_threshold_days} days")
        print("=" * 70)
        
        registered = [r for r in results if r.is_registered]
        suspicious = [r for r in registered if r.trust_level in 
                     ['critical', 'high_risk', 'suspicious', 'low_trust']]
        
        print(f"\nSummary:")
        print(f"  Registered domains found: {len(registered)}")
        print(f"  Suspicious/Low-trust: {len(suspicious)}")
        
        if not results:
            print("\nNo registered domains found.")
            return
        
        print("\nDetailed Results:")
        print("-" * 70)
        print(f"{'Domain':<35} {'Technique':<15} {'Age':<8} {'Trust':<12} {'Risk':<5}")
        print("-" * 70)
        
        for result in results[:50]:
            age_str = str(result.domain_age_days) if result.domain_age_days else "N/A"
            print(f"{result.variant_domain:<35} {result.technique:<15} {age_str:<8} "
                  f"{result.trust_level:<12} {result.risk_score:<5}")
    
    @staticmethod
    def format_json(results: List[DomainVariant], config: AnalysisConfig) -> str:
        """Format results as JSON."""
        output = {
            'analysis_config': {
                'target_domain': config.target_domain,
                'trust_threshold_days': config.trust_threshold_days,
                'analysis_date': datetime.now().isoformat(),
            },
            'summary': {
                'total_variants': len(results),
                'registered_count': len([r for r in results if r.is_registered]),
                'suspicious_count': len([r for r in results if r.trust_level in 
                                        ['critical', 'high_risk', 'suspicious', 'low_trust']]),
            },
            'results': [r.to_dict() for r in results]
        }
        return json.dumps(output, indent=2, default=str)
    
    @staticmethod
    def format_csv(results: List[DomainVariant], config: AnalysisConfig) -> str:
        """Format results as CSV."""
        import io
        output = io.StringIO()
        fieldnames = [
            'variant_domain', 'original_domain', 'technique', 'technique_detail',
            'is_registered', 'creation_date', 'domain_age_days', 'trust_level',
            'risk_score', 'registrar', 'dns_records', 'error'
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for result in results:
            row = {
                'variant_domain': result.variant_domain,
                'original_domain': result.original_domain,
                'technique': result.technique,
                'technique_detail': result.technique_detail,
                'is_registered': result.is_registered,
                'creation_date': result.creation_date.isoformat() if result.creation_date else '',
                'domain_age_days': result.domain_age_days or '',
                'trust_level': result.trust_level,
                'risk_score': result.risk_score,
                'registrar': result.registrar or '',
                'dns_records': json.dumps(result.dns_records),
                'error': result.error or ''
            }
            writer.writerow(row)
        
        return output.getvalue()


# ============================================================================
# MAIN APPLICATION
# ============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        description='Homograph Domain Analyzer - Detect potential phishing domains',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com --output json --file results.json
  %(prog)s example.com --threshold 365 --threads 20
  %(prog)s example.com --techniques homograph,typo,tld
  %(prog)s example.com --include-unregistered --verbose
        """
    )
    
    parser.add_argument('domain', help='Target domain to analyze')
    
    parser.add_argument(
        '-t', '--threshold',
        type=int,
        default=730,
        help='Trust threshold in days (default: 730 = 2 years)'
    )
    
    parser.add_argument(
        '-m', '--max-variants',
        type=int,
        default=1000,
        help='Maximum number of variants to generate (default: 1000)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=10,
        help='Number of concurrent threads (default: 10)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Timeout for DNS/WHOIS queries in seconds (default: 5)'
    )
    
    parser.add_argument(
        '--techniques',
        type=str,
        default='all',
        help='Comma-separated list of techniques (default: all). '
             'Options: homograph,leetspeak,typo,phonetic,repetition,'
             'omission,insertion,transposition,hyphenation,tld,'
             'prefix,suffix,vowel_swap,double_char,bitsquatting,subdomain'
    )
    
    parser.add_argument(
        '-o', '--output',
        choices=['console', 'json', 'csv'],
        default='console',
        help='Output format (default: console)'
    )
    
    parser.add_argument(
        '-f', '--file',
        type=str,
        help='Output file path (optional)'
    )
    
    parser.add_argument(
        '--include-unregistered',
        action='store_true',
        help='Include unregistered domains in output'
    )
    
    parser.add_argument(
        '--no-dns',
        action='store_true',
        help='Skip DNS verification'
    )
    
    parser.add_argument(
        '--no-whois',
        action='store_true',
        help='Skip WHOIS lookups'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    return parser


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create configuration
    config = AnalysisConfig(
        target_domain=args.domain,
        trust_threshold_days=args.threshold,
        max_variants=args.max_variants,
        check_dns=not args.no_dns,
        check_whois=not args.no_whois,
        threads=args.threads,
        timeout=args.timeout,
        include_unregistered=args.include_unregistered,
        techniques=args.techniques.split(','),
        output_format=args.output,
        output_file=args.file,
        verbose=args.verbose
    )
    
    # Print header
    if RICH_AVAILABLE:
        console.print(Panel(
            "[bold blue]Homograph Domain Analyzer[/bold blue]\n"
            "Detecting potential phishing and typosquatting domains",
            title="🔍 Security Analysis Tool"
        ))
    else:
        print("\n" + "=" * 50)
        print("Homograph Domain Analyzer")
        print("=" * 50)
    
    # Generate variants
    logger.info(f"Generating variants for: {config.target_domain}")
    generator = HomographGenerator(config)
    variants = generator.generate_all()
    
    if not variants:
        print("No variants generated. Check the domain name.")
        return 1
    
    # Analyze variants
    logger.info(f"Analyzing {len(variants)} variants...")
    analyzer = DomainAnalyzer(config)
    results = analyzer.analyze_all(variants)
    
    # Sort by risk score
    results.sort(key=lambda x: x.risk_score, reverse=True)
    
    # Output results
    if config.output_format == 'json':
        output = OutputFormatter.format_json(results, config)
        if config.output_file:
            with open(config.output_file, 'w') as f:
                f.write(output)
            print(f"Results saved to: {config.output_file}")
        else:
            print(output)
    
    elif config.output_format == 'csv':
        output = OutputFormatter.format_csv(results, config)
        if config.output_file:
            with open(config.output_file, 'w') as f:
                f.write(output)
            print(f"Results saved to: {config.output_file}")
        else:
            print(output)
    
    else:
        OutputFormatter.format_console(results, config)
        if config.output_file:
            # Also save to file
            output = OutputFormatter.format_json(results, config)
            with open(config.output_file, 'w') as f:
                f.write(output)
            print(f"\nResults also saved to: {config.output_file}")
    
    # Return exit code based on suspicious domains found
    suspicious = [r for r in results if r.is_registered and 
                  r.trust_level in ['critical', 'high_risk', 'suspicious']]
    
    if suspicious:
        if RICH_AVAILABLE:
            console.print(f"\n[bold red]⚠ Warning: {len(suspicious)} suspicious domains found![/bold red]")
        else:
            print(f"\nWarning: {len(suspicious)} suspicious domains found!")
        return 2
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
