"""
SENTINEL APEX v27.0 — Auto Rule Generation
============================================
AI-powered detection rule synthesis.
"""
from .generator import RuleGenerator, get_rule_generator
from .sigma import SigmaRuleGenerator
from .yara import YaraRuleGenerator
from .siem_queries import KQLGenerator, SPLGenerator, EQLGenerator

__all__ = [
    "RuleGenerator",
    "get_rule_generator",
    "SigmaRuleGenerator",
    "YaraRuleGenerator",
    "KQLGenerator",
    "SPLGenerator",
    "EQLGenerator",
]
