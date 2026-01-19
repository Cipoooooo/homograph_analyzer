#!/usr/bin/env python3
"""
Command Line Interface for Homograph Domain Analyzer

This module provides a user-friendly CLI for analyzing homograph domains.
"""

import argparse
import sys
import json
from pathlib import Path
from datetime import datetime

from analyzer_api import HomographDomainAnalyzer


def print_banner():
    """Print application banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║           HOMOGRAPH DOMAIN ANALYZER v1.0.0                    ║
    ║   Detect potentially malicious look-alike domains            ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def analyze_single_domain(args):
    """Analyze a single domain."""
    print(f"\n[*] Analyzing domain: {args.domain}")
    print(f"[*] Trust threshold: {args.threshold} years")
    print(f"[*] Maximum variants: {args.max_variants}")
    print("-" * 60)
    
    # Initialize analyzer
    analyzer = HomographDomainAnalyzer(
        trust_threshold_years=args.threshold,
        dns_timeout=args.dns_timeout,
        whois_timeout=args.whois_timeout,
        max_workers=args.workers
    )
    
    # Generate variants
    print("\n[*] Generating homograph variants...")
    variants = analyzer.generate_all_variants(args.domain)
    print(f"[+] Generated {len(variants)} potential variants")
    
    if args.max_variants and len(variants) > args.max_variants:
        print(f"[!] Limiting to {args.max_variants} variants for analysis")
        variants = list(variants)[:args.max_variants]
    
    # Analyze variants
    print("\n[*] Analyzing variants (this may take a while)...")
    results = analyzer.analyze_domain(
        args.domain,
        check_dns=not args.skip_dns,
        check_whois=not args.skip_whois,
        max_variants=args.max_variants
    )
    
    # Display results
    display_results(results, args)
    
    # Export if requested
    if args.output:
        export_results(results, args.output, args.format)
    
    return results


def display_results(results: dict, args):
    """Display analysis results."""
    print("\n" + "=" * 60)
    print("ANALYSIS RESULTS")
    print("=" * 60)
    
    target = results.get('target_domain', 'Unknown')
    print(f"\nTarget Domain: {target}")
    print(f"Analysis Time: {results.get('analysis_timestamp', 'N/A')}")
    print(f"Total Variants Generated: {results.get('total_variants_generated', 0)}")
    print(f"Variants Analyzed: {results.get('variants_analyzed', 0)}")
    
    # Summary statistics
    summary = results.get('summary', {})
    print(f"\n--- Summary ---")
    print(f"Registered Domains Found: {summary.get('registered_domains', 0)}")
    print(f"High Risk (Suspicious): {summary.get('high_risk_count', 0)}")
    print(f"Medium Risk: {summary.get('medium_risk_count', 0)}")
    print(f"Low Risk: {summary.get('low_risk_count', 0)}")
    print(f"Unknown Risk (WHOIS failed): {summary.get('unknown_risk_count', 0)}")
    
    # Detailed results
    analyzed = results.get('analyzed_variants', [])
    
    if not analyzed:
        print("\n[!] No registered variants found.")
        return
    
    # Sort by risk level
    risk_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'UNKNOWN': 3}
    analyzed_sorted = sorted(
        analyzed,
        key=lambda x: risk_order.get(x.get('risk_level', 'UNKNOWN'), 99)
    )
    
    # Display high-risk domains
    high_risk = [v for v in analyzed_sorted if v.get('risk_level') == 'HIGH']
    if high_risk:
        print("\n" + "-" * 60)
        print("HIGH RISK DOMAINS (Potential Phishing/Impersonation)")
        print("-" * 60)
        for variant in high_risk:
            print_variant_details(variant, verbose=args.verbose)
    
    # Display medium-risk domains
    medium_risk = [v for v in analyzed_sorted if v.get('risk_level') == 'MEDIUM']
    if medium_risk:
        print("\n" + "-" * 60)
        print("MEDIUM RISK DOMAINS")
        print("-" * 60)
        for variant in medium_risk:
            print_variant_details(variant, verbose=args.verbose)
    
    # Display low-risk domains (only in verbose mode)
    if args.verbose:
        low_risk = [v for v in analyzed_sorted if v.get('risk_level') == 'LOW']
        if low_risk:
            print("\n" + "-" * 60)
            print("LOW RISK DOMAINS (Established)")
            print("-" * 60)
            for variant in low_risk:
                print_variant_details(variant, verbose=True)
    
    # Display unknown risk domains (registered but WHOIS failed)
    unknown_risk = [v for v in analyzed_sorted if v.get('risk_level') == 'UNKNOWN' and v.get('is_registered')]
    if unknown_risk:
        print("\n" + "-" * 60)
        print(f"REGISTERED DOMAINS - WHOIS UNAVAILABLE ({len(unknown_risk)} domains)")
        print("-" * 60)
        print("[!] These domains are registered but WHOIS lookup failed.")
        print("[!] They may require manual investigation.\n")
        # Show first 20 by default, all if verbose
        display_limit = len(unknown_risk) if args.verbose else min(20, len(unknown_risk))
        for variant in unknown_risk[:display_limit]:
            print_variant_details(variant, verbose=args.verbose)
        if not args.verbose and len(unknown_risk) > 20:
            print(f"\n[...] {len(unknown_risk) - 20} more domains. Use --verbose to show all.")


def print_variant_details(variant: dict, verbose: bool = False):
    """Print details for a single variant."""
    domain = variant.get('domain', 'Unknown')
    technique = variant.get('technique', 'Unknown')
    risk = variant.get('risk_level', 'UNKNOWN')
    age_days = variant.get('age_days')
    creation_date = variant.get('creation_date')
    
    risk_icons = {
        'HIGH': '[!!!]',
        'MEDIUM': '[!!]',
        'LOW': '[*]',
        'UNKNOWN': '[?]'
    }
    
    print(f"\n{risk_icons.get(risk, '[?]')} {domain}")
    print(f"    Technique: {technique}")
    
    if creation_date:
        print(f"    Created: {creation_date}")
    
    if age_days is not None:
        years = age_days / 365.25
        print(f"    Age: {age_days} days ({years:.1f} years)")
    
    if verbose:
        # DNS Information
        dns_info = variant.get('dns_info', {})
        if dns_info:
            if dns_info.get('a_records'):
                print(f"    A Records: {', '.join(dns_info['a_records'][:3])}")
            if dns_info.get('mx_records'):
                print(f"    MX Records: {', '.join(dns_info['mx_records'][:2])}")
            if dns_info.get('ns_records'):
                print(f"    NS Records: {', '.join(dns_info['ns_records'][:2])}")
        
        # WHOIS Information
        whois_info = variant.get('whois_info', {})
        if whois_info:
            registrar = whois_info.get('registrar')
            if registrar:
                print(f"    Registrar: {registrar}")
            expiry = whois_info.get('expiration_date')
            if expiry:
                print(f"    Expires: {expiry}")


def export_results(results: dict, output_path: str, format_type: str):
    """Export results to file."""
    output_file = Path(output_path)
    
    if format_type == 'json':
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Results exported to: {output_file}")
    
    elif format_type == 'csv':
        import csv
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Domain', 'Technique', 'Risk Level', 'Is Registered',
                'Creation Date', 'Age (Days)', 'Registrar', 'A Records'
            ])
            
            # Data rows
            for variant in results.get('analyzed_variants', []):
                dns_info = variant.get('dns_info', {})
                whois_info = variant.get('whois_info', {})
                
                writer.writerow([
                    variant.get('domain', ''),
                    variant.get('technique', ''),
                    variant.get('risk_level', ''),
                    variant.get('is_registered', False),
                    variant.get('creation_date', ''),
                    variant.get('age_days', ''),
                    whois_info.get('registrar', ''),
                    '; '.join(dns_info.get('a_records', []))
                ])
        
        print(f"\n[+] Results exported to: {output_file}")
    
    elif format_type == 'html':
        export_html_report(results, output_file)
        print(f"\n[+] HTML report exported to: {output_file}")


def export_html_report(results: dict, output_file: Path):
    """Generate an HTML report."""
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Homograph Domain Analysis Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #f8fafc; margin-bottom: 0.5rem; }}
        h2 {{ color: #94a3b8; font-size: 1.25rem; margin: 2rem 0 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }}
        .meta {{ color: #64748b; margin-bottom: 2rem; }}
        .summary {{ 
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 1rem; margin-bottom: 2rem;
        }}
        .stat-card {{ 
            background: #1e293b; padding: 1.5rem; border-radius: 0.5rem;
            border: 1px solid #334155;
        }}
        .stat-card h3 {{ color: #94a3b8; font-size: 0.875rem; text-transform: uppercase; }}
        .stat-card .value {{ font-size: 2rem; font-weight: bold; color: #f8fafc; }}
        .stat-card.high .value {{ color: #ef4444; }}
        .stat-card.medium .value {{ color: #f59e0b; }}
        .stat-card.low .value {{ color: #22c55e; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #1e293b; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }}
        tr:hover {{ background: #1e293b; }}
        .risk-high {{ color: #ef4444; font-weight: bold; }}
        .risk-medium {{ color: #f59e0b; font-weight: bold; }}
        .risk-low {{ color: #22c55e; }}
        .badge {{ 
            display: inline-block; padding: 0.25rem 0.5rem; border-radius: 0.25rem;
            font-size: 0.75rem; font-weight: 600;
        }}
        .badge-high {{ background: #7f1d1d; color: #fecaca; }}
        .badge-medium {{ background: #78350f; color: #fde68a; }}
        .badge-low {{ background: #14532d; color: #bbf7d0; }}
        .technique {{ color: #a78bfa; font-family: monospace; font-size: 0.875rem; }}
        .domain {{ font-family: monospace; color: #38bdf8; }}
        footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #334155; color: #64748b; font-size: 0.875rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Homograph Domain Analysis Report</h1>
        <p class="meta">
            Target: <strong>{target_domain}</strong> | 
            Generated: {timestamp} |
            Trust Threshold: {threshold} years
        </p>
        
        <div class="summary">
            <div class="stat-card">
                <h3>Total Variants</h3>
                <div class="value">{total_variants}</div>
            </div>
            <div class="stat-card">
                <h3>Registered Found</h3>
                <div class="value">{registered_count}</div>
            </div>
            <div class="stat-card high">
                <h3>High Risk</h3>
                <div class="value">{high_risk}</div>
            </div>
            <div class="stat-card medium">
                <h3>Medium Risk</h3>
                <div class="value">{medium_risk}</div>
            </div>
            <div class="stat-card low">
                <h3>Low Risk</h3>
                <div class="value">{low_risk}</div>
            </div>
        </div>
        
        <h2>Detected Domains</h2>
        <table>
            <thead>
                <tr>
                    <th>Risk</th>
                    <th>Domain</th>
                    <th>Technique</th>
                    <th>Created</th>
                    <th>Age</th>
                    <th>Registrar</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
        
        <footer>
            Generated by Homograph Domain Analyzer v1.0.0
        </footer>
    </div>
</body>
</html>
    """
    
    # Generate table rows
    rows = []
    risk_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'UNKNOWN': 3}
    variants = sorted(
        results.get('analyzed_variants', []),
        key=lambda x: risk_order.get(x.get('risk_level', 'UNKNOWN'), 99)
    )
    
    for v in variants:
        risk = v.get('risk_level', 'UNKNOWN')
        badge_class = f"badge-{risk.lower()}" if risk in ['HIGH', 'MEDIUM', 'LOW'] else ''
        age_days = v.get('age_days')
        age_str = f"{age_days} days" if age_days else 'N/A'
        whois = v.get('whois_info', {})
        
        rows.append(f"""
            <tr>
                <td><span class="badge {badge_class}">{risk}</span></td>
                <td class="domain">{v.get('domain', '')}</td>
                <td class="technique">{v.get('technique', '')}</td>
                <td>{v.get('creation_date', 'N/A')}</td>
                <td>{age_str}</td>
                <td>{whois.get('registrar', 'N/A')}</td>
            </tr>
        """)
    
    summary = results.get('summary', {})
    
    html = html_template.format(
        target_domain=results.get('target_domain', 'Unknown'),
        timestamp=results.get('analysis_timestamp', datetime.now().isoformat()),
        threshold=results.get('trust_threshold_years', 2),
        total_variants=results.get('total_variants_generated', 0),
        registered_count=summary.get('registered_domains', 0),
        high_risk=summary.get('high_risk_count', 0),
        medium_risk=summary.get('medium_risk_count', 0),
        low_risk=summary.get('low_risk_count', 0),
        table_rows=''.join(rows)
    )
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)


def analyze_batch(args):
    """Analyze multiple domains from a file."""
    print(f"\n[*] Batch analysis from: {args.file}")
    print(f"[*] Use the batch_analyzer.py script for batch processing:")
    print(f"    python batch_analyzer.py -i {args.file} -o results.json")
    

def list_techniques(args):
    """List available homograph techniques."""
    print("\n" + "=" * 60)
    print("AVAILABLE HOMOGRAPH TECHNIQUES")
    print("=" * 60)
    
    techniques = {
        "Unicode Homoglyphs": "Substitutes ASCII characters with visually similar Unicode characters (e.g., 'a' -> 'а' Cyrillic)",
        "ASCII Substitutions": "Replaces characters with similar ASCII alternatives (e.g., 'l' -> '1', 'o' -> '0')",
        "Character Omission": "Removes single characters from the domain name",
        "Character Duplication": "Doubles characters in the domain (e.g., 'google' -> 'gooogle')",
        "Character Insertion": "Inserts extra characters between existing ones",
        "Adjacent Key Swap": "Swaps characters based on keyboard proximity (typosquatting)",
        "Character Transposition": "Swaps adjacent characters (e.g., 'google' -> 'googel')",
        "Vowel Swap": "Replaces vowels with other vowels",
        "Bit Flipping": "Simulates single-bit errors in character encoding",
        "Hyphenation": "Adds hyphens at various positions",
        "Dot Insertion": "Adds dots to create subdomain-like appearance",
        "TLD Variations": "Tests alternative top-level domains",
        "Prefix Addition": "Adds common prefixes (www, secure, login, etc.)",
        "Suffix Addition": "Adds common suffixes (-login, -secure, etc.)",
        "Word Combination": "Combines with common words (official, real, etc.)",
        "Punycode Encoding": "Converts Unicode domains to ASCII-compatible encoding"
    }
    
    for name, desc in techniques.items():
        print(f"\n[*] {name}")
        print(f"    {desc}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Homograph Domain Analyzer - Detect potentially malicious look-alike domains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze example.com
  %(prog)s analyze example.com -t 1 -o results.json -f json
  %(prog)s analyze example.com --verbose --max-variants 500
  %(prog)s techniques
  
For batch processing, use:
  python batch_analyzer.py -i domains.txt -o results.json
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze single domain
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a single domain')
    analyze_parser.add_argument('domain', help='Target domain to analyze')
    analyze_parser.add_argument('-t', '--threshold', type=float, default=2.0,
                                help='Trust threshold in years (default: 2)')
    analyze_parser.add_argument('-m', '--max-variants', type=int, default=1000,
                                help='Maximum variants to analyze (default: 1000)')
    analyze_parser.add_argument('-o', '--output', help='Output file path')
    analyze_parser.add_argument('-f', '--format', choices=['json', 'csv', 'html'],
                                default='json', help='Output format (default: json)')
    analyze_parser.add_argument('-v', '--verbose', action='store_true',
                                help='Show detailed output')
    analyze_parser.add_argument('-w', '--workers', type=int, default=10,
                                help='Number of concurrent workers (default: 10)')
    analyze_parser.add_argument('--dns-timeout', type=float, default=5.0,
                                help='DNS query timeout in seconds (default: 5)')
    analyze_parser.add_argument('--whois-timeout', type=float, default=10.0,
                                help='WHOIS query timeout in seconds (default: 10)')
    analyze_parser.add_argument('--skip-dns', action='store_true',
                                help='Skip DNS resolution')
    analyze_parser.add_argument('--skip-whois', action='store_true',
                                help='Skip WHOIS lookups')
    
    # Batch analysis - redirect to batch_analyzer.py
    batch_parser = subparsers.add_parser('batch', help='Analyze multiple domains from file')
    batch_parser.add_argument('file', help='File containing domains (one per line)')
    batch_parser.add_argument('-t', '--threshold', type=float, default=2.0,
                              help='Trust threshold in years (default: 2)')
    batch_parser.add_argument('-m', '--max-variants', type=int, default=500,
                              help='Max variants per domain (default: 500)')
    batch_parser.add_argument('-o', '--output-dir', default='./batch_results',
                              help='Output directory for results')
    batch_parser.add_argument('-w', '--workers', type=int, default=5,
                              help='Concurrent workers (default: 5)')
    
    # List techniques
    subparsers.add_parser('techniques', help='List available homograph techniques')
    
    args = parser.parse_args()
    
    if not args.command:
        print_banner()
        parser.print_help()
        return 1
    
    print_banner()
    
    if args.command == 'analyze':
        analyze_single_domain(args)
    elif args.command == 'batch':
        analyze_batch(args)
    elif args.command == 'techniques':
        list_techniques(args)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
