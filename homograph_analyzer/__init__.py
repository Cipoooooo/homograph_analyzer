"""
Homograph Domain Analyzer
=========================

A comprehensive tool for identifying and analyzing homograph domain variants
that could be used for phishing, typosquatting, or brand impersonation.

Usage:
    from homograph_analyzer import HomographGenerator, DomainAnalyzer, AnalysisConfig
    
    config = AnalysisConfig(target_domain='example.com')
    generator = HomographGenerator(config)
    variants = generator.generate_all()
    
    analyzer = DomainAnalyzer(config)
    results = analyzer.analyze_all(variants)
"""

__version__ = '1.0.0'
__author__ = 'Security Research'
__license__ = 'MIT'

from .homograph_domain_analyzer import (
    HomographGenerator,
    DomainAnalyzer,
    DomainVariant,
    AnalysisConfig,
    OutputFormatter,
    HOMOGRAPH_MAPPINGS,
    LEETSPEAK_MAPPINGS,
    KEYBOARD_TYPOS,
    ALTERNATIVE_TLDS,
)

__all__ = [
    'HomographGenerator',
    'DomainAnalyzer', 
    'DomainVariant',
    'AnalysisConfig',
    'OutputFormatter',
    'HOMOGRAPH_MAPPINGS',
    'LEETSPEAK_MAPPINGS',
    'KEYBOARD_TYPOS',
    'ALTERNATIVE_TLDS',
]
