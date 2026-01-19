#!/usr/bin/env python3
"""
Homograph Domain Analyzer - Simplified API

This module provides a clean, easy-to-use API for programmatic access
to the homograph domain analysis functionality.

Example usage:
    from analyzer_api import HomographDomainAnalyzer

    analyzer = HomographDomainAnalyzer(trust_threshold_years=2)
    results = analyzer.analyze_domain("example.com")
    
    for domain in results['suspicious_domains']:
        print(f"Suspicious: {domain['domain']} ({domain['age_days']} days old)")
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import logging

# Import from main module
from homograph_domain_analyzer import (
    HomographGenerator, 
    DomainAnalyzer, 
    AnalysisConfig,
    DomainVariant,
    HOMOGRAPH_MAPPINGS,
    LEETSPEAK_MAPPINGS,
    KEYBOARD_TYPOS,
    ALTERNATIVE_TLDS,
    DNS_AVAILABLE,
    WHOIS_AVAILABLE
)

logger = logging.getLogger(__name__)


class HomographDomainAnalyzer:
    """
    Simplified API for homograph domain analysis.
    
    This class provides an easy-to-use interface for:
    - Generating homograph domain variants
    - Checking domain registration status
    - Retrieving WHOIS creation dates
    - Classifying domains by trust level based on age
    
    Attributes:
        trust_threshold_years (float): Minimum age in years for trusted domains
        dns_timeout (float): Timeout for DNS queries
        whois_timeout (float): Timeout for WHOIS queries
        max_workers (int): Number of concurrent workers
    """
    
    def __init__(
        self,
        trust_threshold_years: float = 2.0,
        dns_timeout: float = 5.0,
        whois_timeout: float = 10.0,
        max_workers: int = 10
    ):
        """
        Initialize the analyzer.
        
        Args:
            trust_threshold_years: Minimum domain age for "trusted" classification
            dns_timeout: Timeout for DNS lookups in seconds
            whois_timeout: Timeout for WHOIS queries in seconds
            max_workers: Number of concurrent analysis threads
        """
        self.trust_threshold_years = trust_threshold_years
        self.trust_threshold_days = int(trust_threshold_years * 365.25)
        self.dns_timeout = dns_timeout
        self.whois_timeout = whois_timeout
        self.max_workers = max_workers
        
        # Check available features
        self._dns_available = DNS_AVAILABLE
        self._whois_available = WHOIS_AVAILABLE
    
    def generate_all_variants(self, domain: str) -> Set[str]:
        """
        Generate all possible homograph variants for a domain.
        
        Args:
            domain: Target domain (e.g., "example.com")
            
        Returns:
            Set of unique domain variant strings
        """
        config = AnalysisConfig(
            target_domain=domain,
            trust_threshold_days=self.trust_threshold_days,
            max_variants=10000,  # High limit for generation
            check_dns=False,
            check_whois=False,
            threads=1,
            timeout=self.dns_timeout
        )
        
        generator = HomographGenerator(config)
        variants = generator.generate_all()
        
        return {v.variant_domain for v in variants}
    
    def analyze_domain(
        self,
        domain: str,
        check_dns: bool = True,
        check_whois: bool = True,
        max_variants: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Perform complete analysis of a domain and its variants.
        
        Args:
            domain: Target domain to analyze
            check_dns: Whether to verify DNS registration
            check_whois: Whether to retrieve WHOIS data
            max_variants: Maximum variants to analyze (None = all)
            
        Returns:
            Dictionary containing:
            - target_domain: Original domain
            - analysis_timestamp: When analysis was performed
            - trust_threshold_years: Configured threshold
            - total_variants_generated: Number of variants created
            - variants_analyzed: Number actually analyzed
            - summary: Statistics about results
            - analyzed_variants: List of detailed variant data
        """
        start_time = datetime.now()
        
        # Create configuration
        config = AnalysisConfig(
            target_domain=domain,
            trust_threshold_days=self.trust_threshold_days,
            max_variants=max_variants or 10000,
            check_dns=check_dns,
            check_whois=check_whois,
            threads=self.max_workers,
            timeout=int(self.dns_timeout)
        )
        
        # Generate variants
        generator = HomographGenerator(config)
        variants = generator.generate_all()
        total_generated = len(variants)
        
        # Limit if specified
        if max_variants and len(variants) > max_variants:
            variants = variants[:max_variants]
        
        # Analyze variants
        analyzer = DomainAnalyzer(config)
        results = analyzer.analyze_all(variants)
        
        # Process results
        analyzed_variants = []
        registered_count = 0
        high_risk_count = 0
        medium_risk_count = 0
        low_risk_count = 0
        
        unknown_risk_count = 0
        
        for result in results:
            variant_data = self._process_variant(result)
            analyzed_variants.append(variant_data)
            
            if result.is_registered:
                registered_count += 1
                risk = variant_data.get('risk_level', 'UNKNOWN')
                if risk == 'HIGH':
                    high_risk_count += 1
                elif risk == 'MEDIUM':
                    medium_risk_count += 1
                elif risk == 'LOW':
                    low_risk_count += 1
                elif risk == 'UNKNOWN':
                    unknown_risk_count += 1
        
        # Sort by risk (HIGH first)
        risk_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'UNKNOWN': 3, 'UNREGISTERED': 4}
        analyzed_variants.sort(key=lambda x: risk_order.get(x.get('risk_level', 'UNKNOWN'), 99))
        
        return {
            'target_domain': domain,
            'analysis_timestamp': start_time.isoformat(),
            'trust_threshold_years': self.trust_threshold_years,
            'total_variants_generated': total_generated,
            'variants_analyzed': len(results),
            'summary': {
                'registered_domains': registered_count,
                'high_risk_count': high_risk_count,
                'medium_risk_count': medium_risk_count,
                'low_risk_count': low_risk_count,
                'unknown_risk_count': unknown_risk_count,
            },
            'analyzed_variants': analyzed_variants
        }
    
    def _process_variant(self, variant: DomainVariant) -> Dict[str, Any]:
        """Process a variant result into a clean dictionary."""
        # Map internal trust levels to simplified risk levels
        trust_to_risk = {
            'critical': 'HIGH',
            'high_risk': 'HIGH',
            'suspicious': 'HIGH',
            'low_trust': 'MEDIUM',
            'moderate': 'MEDIUM',
            'established': 'LOW',
            'unknown': 'UNKNOWN',
            'unregistered': 'UNREGISTERED'
        }
        
        risk_level = trust_to_risk.get(variant.trust_level, 'UNKNOWN')
        
        result = {
            'domain': variant.variant_domain,
            'technique': variant.technique,
            'technique_detail': variant.technique_detail,
            'is_registered': variant.is_registered,
            'risk_level': risk_level,
            'age_days': variant.domain_age_days,
            'creation_date': variant.creation_date.isoformat() if variant.creation_date else None,
        }
        
        # Add DNS info if available
        if variant.dns_records:
            result['dns_info'] = {
                'a_records': variant.dns_records.get('A', []),
                'aaaa_records': variant.dns_records.get('AAAA', []),
                'mx_records': variant.dns_records.get('MX', []),
                'ns_records': variant.dns_records.get('NS', []),
            }
        
        # Add WHOIS info if available
        if variant.whois_data or variant.registrar:
            result['whois_info'] = {
                'registrar': variant.registrar,
                'expiration_date': variant.whois_data.get('expiration_date'),
                'name_servers': variant.whois_data.get('name_servers'),
            }
        
        return result
    
    def quick_check(self, variant_domain: str) -> Dict[str, Any]:
        """
        Quickly check a single domain variant.
        
        Args:
            variant_domain: Domain to check
            
        Returns:
            Dictionary with registration and risk information
        """
        config = AnalysisConfig(
            target_domain=variant_domain,
            trust_threshold_days=self.trust_threshold_days,
            check_dns=True,
            check_whois=True,
            threads=1,
            timeout=int(self.dns_timeout)
        )
        
        analyzer = DomainAnalyzer(config)
        
        variant = DomainVariant(
            original_domain=variant_domain,
            variant_domain=variant_domain,
            technique='direct_check'
        )
        
        result = analyzer.analyze_variant(variant)
        return self._process_variant(result)
    
    def get_suspicious_domains(
        self,
        domain: str,
        max_variants: int = 500
    ) -> List[Dict[str, Any]]:
        """
        Get only suspicious/high-risk domains for a target.
        
        This is a convenience method that filters results to show
        only registered domains below the trust threshold.
        
        Args:
            domain: Target domain
            max_variants: Maximum variants to check
            
        Returns:
            List of suspicious domain dictionaries
        """
        results = self.analyze_domain(
            domain,
            check_dns=True,
            check_whois=True,
            max_variants=max_variants
        )
        
        suspicious = [
            v for v in results['analyzed_variants']
            if v.get('is_registered') and v.get('risk_level') in ['HIGH', 'MEDIUM']
        ]
        
        return suspicious
    
    def export_results(
        self,
        results: Dict[str, Any],
        filepath: str,
        format: str = 'json'
    ) -> None:
        """
        Export analysis results to a file.
        
        Args:
            results: Analysis results dictionary
            filepath: Output file path
            format: Output format ('json' or 'csv')
        """
        if format == 'json':
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
        
        elif format == 'csv':
            import csv
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'Domain', 'Technique', 'Is Registered', 'Risk Level',
                    'Age (Days)', 'Creation Date', 'Registrar'
                ])
                
                for v in results.get('analyzed_variants', []):
                    whois = v.get('whois_info', {})
                    writer.writerow([
                        v.get('domain'),
                        v.get('technique'),
                        v.get('is_registered'),
                        v.get('risk_level'),
                        v.get('age_days'),
                        v.get('creation_date'),
                        whois.get('registrar') if whois else ''
                    ])
    
    @staticmethod
    def get_available_techniques() -> List[str]:
        """Get list of available homograph techniques."""
        return [
            'homograph', 'leetspeak', 'typo', 'phonetic',
            'repetition', 'omission', 'insertion', 'transposition',
            'hyphenation', 'tld', 'prefix', 'suffix', 'vowel_swap',
            'double_char', 'bitsquatting', 'subdomain'
        ]
    
    @staticmethod
    def get_homograph_mappings() -> Dict[str, List[str]]:
        """Get the Unicode homograph character mappings."""
        return HOMOGRAPH_MAPPINGS.copy()


# Example usage and testing
if __name__ == '__main__':
    import sys
    
    print("Homograph Domain Analyzer - API Example")
    print("=" * 50)
    
    # Example usage
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    
    print(f"\nTarget domain: {domain}")
    print(f"DNS available: {DNS_AVAILABLE}")
    print(f"WHOIS available: {WHOIS_AVAILABLE}")
    
    # Initialize analyzer
    analyzer = HomographDomainAnalyzer(
        trust_threshold_years=2.0,
        max_workers=5
    )
    
    # Generate variants only (fast)
    print("\n1. Generating variants...")
    variants = analyzer.generate_all_variants(domain)
    print(f"   Generated {len(variants)} unique variants")
    
    # Show sample variants
    print("\n   Sample variants:")
    for v in list(variants)[:10]:
        print(f"     - {v}")
    
    # Full analysis (slower - involves network requests)
    print("\n2. Analyzing variants (limited to 50 for demo)...")
    results = analyzer.analyze_domain(
        domain,
        check_dns=True,
        check_whois=True,
        max_variants=50
    )
    
    print(f"\n   Summary:")
    print(f"     Total generated: {results['total_variants_generated']}")
    print(f"     Analyzed: {results['variants_analyzed']}")
    print(f"     Registered: {results['summary']['registered_domains']}")
    print(f"     High risk: {results['summary']['high_risk_count']}")
    print(f"     Medium risk: {results['summary']['medium_risk_count']}")
    print(f"     Low risk: {results['summary']['low_risk_count']}")
    
    # Show suspicious domains
    suspicious = [v for v in results['analyzed_variants'] 
                  if v.get('risk_level') in ['HIGH', 'MEDIUM']]
    
    if suspicious:
        print(f"\n3. Suspicious domains found:")
        for s in suspicious[:5]:
            print(f"     [{s['risk_level']}] {s['domain']}")
            if s.get('age_days'):
                print(f"           Age: {s['age_days']} days")
    else:
        print("\n3. No suspicious domains found in sample")
    
    print("\n" + "=" * 50)
    print("Analysis complete!")
