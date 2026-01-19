#!/usr/bin/env python3
"""
Batch Homograph Domain Analyzer
===============================

Analyze multiple target domains for homograph variants.
Supports reading targets from file and generating comprehensive reports.
"""

import argparse
import json
import csv
import sys
import os
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path

from homograph_domain_analyzer import (
    HomographGenerator,
    DomainAnalyzer,
    AnalysisConfig,
    DomainVariant,
)

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


def load_domains_from_file(filepath: str) -> List[str]:
    """Load domain list from file."""
    domains = []
    
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if line and not line.startswith('#'):
                domains.append(line)
    
    return domains


def analyze_domain(domain: str, config_template: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a single domain and return results.
    
    Args:
        domain: Target domain to analyze
        config_template: Configuration template
        
    Returns:
        Analysis results dictionary
    """
    # Create config for this domain
    config = AnalysisConfig(
        target_domain=domain,
        trust_threshold_days=config_template.get('trust_threshold_days', 730),
        max_variants=config_template.get('max_variants', 500),
        check_dns=config_template.get('check_dns', True),
        check_whois=config_template.get('check_whois', True),
        threads=config_template.get('threads', 10),
        timeout=config_template.get('timeout', 5),
        techniques=config_template.get('techniques', ['all']),
    )
    
    # Generate variants
    generator = HomographGenerator(config)
    variants = generator.generate_all()
    
    # Analyze variants
    analyzer = DomainAnalyzer(config)
    results = analyzer.analyze_all(variants)
    
    # Filter and sort results
    registered = [r for r in results if r.is_registered]
    registered.sort(key=lambda x: x.risk_score, reverse=True)
    
    # Categorize by trust level
    suspicious = [r for r in registered if r.trust_level in 
                  ['critical', 'high_risk', 'suspicious', 'low_trust']]
    
    return {
        'target_domain': domain,
        'analysis_timestamp': datetime.now().isoformat(),
        'summary': {
            'total_variants_generated': len(results),
            'registered_count': len(registered),
            'suspicious_count': len(suspicious),
            'critical_count': len([r for r in registered if r.trust_level == 'critical']),
            'high_risk_count': len([r for r in registered if r.trust_level == 'high_risk']),
        },
        'registered_variants': [r.to_dict() for r in registered],
        'suspicious_variants': [r.to_dict() for r in suspicious],
    }


def generate_summary_report(all_results: List[Dict], output_file: str):
    """Generate a summary report of all analyzed domains."""
    
    # Calculate totals
    total_variants = sum(r['summary']['total_variants_generated'] for r in all_results)
    total_registered = sum(r['summary']['registered_count'] for r in all_results)
    total_suspicious = sum(r['summary']['suspicious_count'] for r in all_results)
    total_critical = sum(r['summary']['critical_count'] for r in all_results)
    
    report = {
        'report_metadata': {
            'generated_at': datetime.now().isoformat(),
            'total_domains_analyzed': len(all_results),
            'total_variants_generated': total_variants,
            'total_registered_found': total_registered,
            'total_suspicious': total_suspicious,
            'total_critical': total_critical,
        },
        'domains_by_risk': sorted(
            [
                {
                    'domain': r['target_domain'],
                    'registered': r['summary']['registered_count'],
                    'suspicious': r['summary']['suspicious_count'],
                    'critical': r['summary']['critical_count'],
                }
                for r in all_results
            ],
            key=lambda x: x['critical'] + x['suspicious'],
            reverse=True
        ),
        'detailed_results': all_results
    }
    
    # Write report
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    return report


def main():
    parser = argparse.ArgumentParser(
        description='Batch Homograph Domain Analyzer'
    )
    
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='Input file with domains (one per line) or comma-separated domains'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='batch_analysis_results.json',
        help='Output file for results (default: batch_analysis_results.json)'
    )
    
    parser.add_argument(
        '-t', '--threshold',
        type=int,
        default=730,
        help='Trust threshold in days (default: 730)'
    )
    
    parser.add_argument(
        '-m', '--max-variants',
        type=int,
        default=500,
        help='Max variants per domain (default: 500)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=10,
        help='Threads for concurrent analysis (default: 10)'
    )
    
    parser.add_argument(
        '--no-whois',
        action='store_true',
        help='Skip WHOIS lookups'
    )
    
    parser.add_argument(
        '--techniques',
        type=str,
        default='all',
        help='Comma-separated techniques to use'
    )
    
    args = parser.parse_args()
    
    # Load domains
    if os.path.isfile(args.input):
        domains = load_domains_from_file(args.input)
    else:
        domains = [d.strip() for d in args.input.split(',')]
    
    if not domains:
        print("No domains to analyze!")
        sys.exit(1)
    
    # Configuration template
    config_template = {
        'trust_threshold_days': args.threshold,
        'max_variants': args.max_variants,
        'check_dns': True,
        'check_whois': not args.no_whois,
        'threads': args.threads,
        'timeout': 5,
        'techniques': args.techniques.split(','),
    }
    
    print(f"\n{'='*60}")
    print(f"Batch Homograph Domain Analyzer")
    print(f"{'='*60}")
    print(f"Domains to analyze: {len(domains)}")
    print(f"Trust threshold: {args.threshold} days")
    print(f"Max variants per domain: {args.max_variants}")
    print(f"{'='*60}\n")
    
    all_results = []
    
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task(
                "[cyan]Analyzing domains...", total=len(domains)
            )
            
            for domain in domains:
                progress.update(task, description=f"[cyan]Analyzing {domain}...")
                try:
                    result = analyze_domain(domain, config_template)
                    all_results.append(result)
                    
                    # Print quick summary
                    console.print(
                        f"  [green]✓[/green] {domain}: "
                        f"{result['summary']['registered_count']} registered, "
                        f"[red]{result['summary']['suspicious_count']} suspicious[/red]"
                    )
                except Exception as e:
                    console.print(f"  [red]✗[/red] {domain}: Error - {e}")
                    all_results.append({
                        'target_domain': domain,
                        'error': str(e)
                    })
                
                progress.advance(task)
    else:
        for i, domain in enumerate(domains, 1):
            print(f"[{i}/{len(domains)}] Analyzing {domain}...")
            try:
                result = analyze_domain(domain, config_template)
                all_results.append(result)
                print(f"  ✓ {result['summary']['registered_count']} registered, "
                      f"{result['summary']['suspicious_count']} suspicious")
            except Exception as e:
                print(f"  ✗ Error: {e}")
                all_results.append({
                    'target_domain': domain,
                    'error': str(e)
                })
    
    # Generate report
    print(f"\nGenerating report: {args.output}")
    report = generate_summary_report(all_results, args.output)
    
    # Print summary
    print(f"\n{'='*60}")
    print("BATCH ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(f"Total domains analyzed: {report['report_metadata']['total_domains_analyzed']}")
    print(f"Total variants generated: {report['report_metadata']['total_variants_generated']}")
    print(f"Total registered found: {report['report_metadata']['total_registered_found']}")
    print(f"Total suspicious: {report['report_metadata']['total_suspicious']}")
    print(f"Total critical: {report['report_metadata']['total_critical']}")
    print(f"\nResults saved to: {args.output}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
