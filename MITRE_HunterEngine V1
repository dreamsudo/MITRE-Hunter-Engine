#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###############################################################################
#
#                      *
#                     ***
#                    *****
#                   *******
#                  *********
#                 ***********
#                *****Psypher*****
#                 *****Labs *****
#                  ***********
#                   *******
#                    *****
#                     ***
#                      *
#
#   HunterEngine.py - Heuristic Threat Enrichment Engine by PsypherLabs
#
###############################################################################
#
# Author: PsypherLabs
#
# Description:
#   - Ingests unstructured text data (emails, SMS, logs) for analysis.
#   - Enriches inputs with heuristic tags, IoCs, and MITRE ATT&CK TTPs.
#   - Calculates a risk score and generates high-fidelity YARA rules.
#   - Outputs all findings to a structured session folder with reports.
#   - Intended for Blue Teams, Threat Hunters, and Security Researchers.
#
# MIT License - Copyright (c) 2025 PsypherLabs
# See LICENSE file for details.
#
###############################################################################

# --- Standard Library Imports ---
import os
import re
import sys
import csv
import json
import argparse
import logging
import zipfile
import io
from datetime import datetime
from collections import Counter
from typing import List, Dict, Any, Tuple, Generator, Iterable

# --- Dependency Check & Third-Party Imports ---
try:
    import requests
    from tqdm import tqdm
    from rapidfuzz import fuzz
    from stix2 import MemoryStore, Filter, exceptions
except ImportError as e:
    # Provide a more explicit and user-friendly error message
    print("\n--- Missing Dependencies ---")
    print(f"Error: A required library is missing: '{e.name}'")
    print("Please install all dependencies by running:")
    print("pip install requests tqdm rapidfuzz stix2")
    print("Or, if a requirements.txt file is present:")
    print("pip install -r requirements.txt")
    print("--------------------------\n")
    sys.exit(1)

# --- Banners and Manuals ---

def print_banner():
    """Prints the ASCII art logo in bright green."""
    # This line is a common trick to enable ANSI escape sequence processing on Windows.
    # It has no effect on Linux/macOS.
    if os.name == 'nt':
        os.system('')
        
    # ANSI escape code for bright green and to reset color
    bright_green = "\033[92m"
    reset_color = "\033[0m"
    
    banner = f"""{bright_green}
                      *
                     ***
                    *****
                   *******
                  *********
                 ***********
                *****Psypher*****
                 *****Labs *****
                  ***********
                   *******
                    *****
                     ***
                      *

        ThreatClassifier by PsypherLabs
  Heuristic Threat Enrichment & Hunting Engine
{reset_color}"""
    print(banner)

def print_manual_and_license():
    """Prints the quick start manual, license, and legal disclosure."""
    manual = """
===============================================================================
 MIT LICENSE & ETHICAL USE NOTICE
===============================================================================
Copyright (c) 2025 PsypherLabs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

--- LEGAL & ETHICAL USE DISCLOSURE ---
This tool is intended for legitimate cybersecurity purposes ONLY, including
blue team analysis, threat hunting, and security research. Unauthorized use
of this tool on any system or with any data for which you do not have explicit
permission is strictly prohibited. The authors are not responsible for any
misuse or damage caused by this program. YOU ARE RESPONSIBLE FOR YOUR ACTIONS.

===============================================================================
 QUICK START MANUAL
===============================================================================
1. Install dependencies:
   pip install -r requirements.txt

2. Run the engine against an input file:
   python3 HunterEngine.py /path/to/your/input.txt

3. Use a custom configuration for different threat models:
   python3 HunterEngine.py emails.csv -c primitives/bec_primitives.json

4. Find all generated reports, IoCs, and YARA rules in:
   ./ClassifierBox/session_<timestamp>/
===============================================================================
"""
    print(manual)

# --- GLOBAL CONFIGURATION & LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for data sources and file paths
MITRE_CTI_URL = "https://github.com/mitre/cti/archive/refs/heads/master.zip"
MITRE_DIRS = ["attack-stix-data/enterprise-attack", "attack-stix-data/mobile-attack", "attack-stix-data/ics-attack"]
OUTPUT_ROOT = "ClassifierBox"
MISS_LOG = "missed_inputs.log"
ERROR_LOG = "failed_inputs.log"
MITRE_CACHE_FILE = "mitre_cache.json"
DEFAULT_PRIMITIVES_CONFIG_FILE = "threat_primitives.json"

class ThreatEnrichmentEngine:
    """
    A class to encapsulate all threat enrichment logic, from data setup to
    analysis and artifact generation.
    """
    def __init__(self, config_path: str = DEFAULT_PRIMITIVES_CONFIG_FILE):
        """
        Initializes the engine with configuration settings.

        :param config_path: Path to the JSON configuration file.
        """
        self.config_path = config_path
        self.mitre_keywords = {}
        self.mitre_metadata = []
        self.heuristic_classifiers = []
        # Default values, will be overridden by the config file
        self.risk_thresholds = {"LOW": 4, "MEDIUM": 8, "HIGH": 12}
        self.fuzzy_threshold = 85
        self.score_boosts = {"has_indicator": 5, "mitre_ttp": 6}

    def get_risk_level(self, score: int) -> str:
        """
        Determines the risk level string based on a numerical score.

        :param score: The calculated risk score.
        :return: A string representing the risk level (e.g., "LOW", "HIGH").
        """
        if score == 0: return "INFO"
        if score <= self.risk_thresholds["LOW"]: return "LOW"
        if score <= self.risk_thresholds["MEDIUM"]: return "MEDIUM"
        if score <= self.risk_thresholds["HIGH"]: return "HIGH"
        return "CRITICAL"

    def setup_dependencies(self):
        """
        Orchestrates the setup of all required data files and configurations.
        This is the main entry point for preparing the engine before processing.
        """
        self._load_configuration()
        self._setup_mitre_data()
        self.mitre_keywords, self.mitre_metadata = self._get_mitre_data()

    def _load_configuration(self):
        """
        Loads threat primitives, thresholds, and scoring logic from the
        external JSON configuration file. Creates a default if not found.
        """
        if not os.path.exists(self.config_path):
            logging.warning(f"{self.config_path} not found. Creating a default configuration.")
            # A comprehensive default configuration
            default_config = {
                "config": {
                    "fuzzy_threshold": 85,
                    "risk_thresholds": {"LOW": 4, "MEDIUM": 8, "HIGH": 12},
                    "score_boosts": {"has_indicator": 5, "mitre_ttp": 6}
                },
                "primitives": {
                    "urgency": {"score": 3, "keywords": ["urgent", "immediate", "action required", "expires", "final notice", "now", "today", "overdue"]},
                    "authority": {"score": 4, "keywords": ["irs", "fbi", "hr", "it department", "security alert", "admin"]},
                    "consequence": {"score": 4, "keywords": ["suspended", "locked", "deleted", "compromised", "violation", "breach", "failed"]},
                    "financial": {"score": 3, "keywords": ["invoice", "payment", "wire transfer", "crypto", "reward", "winner", "prize"]},
                    "action_request": {"score": 3, "keywords": ["click", "download", "verify", "authenticate", "scan", "login", "update", "reset"]},
                    "technical_lure": {"score": 3, "keywords": ["malware", "vpn", "reboot", "quarantined", "encrypted", "voicemail", "remote access"]},
                    "benign": {"score": 0, "keywords": ["unsubscribe", "text stop"]}
                }
            }
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(default_config, f, indent=2)

        logging.info(f"Loading configuration from {self.config_path}")
        with open(self.config_path, "r", encoding="utf-8") as f:
            config_data = json.load(f)

        # Load engine settings, falling back to defaults if keys are missing
        engine_config = config_data.get("config", {})
        self.fuzzy_threshold = engine_config.get("fuzzy_threshold", self.fuzzy_threshold)
        self.risk_thresholds = engine_config.get("risk_thresholds", self.risk_thresholds)
        self.score_boosts = engine_config.get("score_boosts", self.score_boosts)
        logging.info(f"Risk thresholds set to: {self.risk_thresholds}")
        logging.info(f"Fuzzy matching threshold set to: {self.fuzzy_threshold}")
        logging.info(f"Score boosts set to: {self.score_boosts}")

        # Compile regex patterns for heuristic classifiers for performance
        primitives = config_data.get("primitives", {})
        compiled_classifiers = []
        for name, data in primitives.items():
            # Using word boundaries (\b) to prevent partial matches (e.g., 'now' in 'know')
            pattern = r'\b(' + '|'.join(re.escape(k) for k in data["keywords"]) + r')\b'
            compiled_classifiers.append({
                "name": name,
                "score": data.get("score", 1),
                "regex": re.compile(pattern, re.IGNORECASE)
            })
        self.heuristic_classifiers = compiled_classifiers
        logging.info(f"Heuristic classifiers built for: {', '.join(primitives.keys())}")

    def _setup_mitre_data(self):
        """
        Checks for local MITRE ATT&CK STIX data and downloads it if missing.
        """
        if os.path.exists("attack-stix-data"): return
        logging.warning("MITRE ATT&CK data not found. Downloading automatically... (approx. 70MB)")
        try:
            response = requests.get(MITRE_CTI_URL, stream=True, timeout=60)
            response.raise_for_status()
            with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                for member in tqdm(zf.infolist(), desc="Extracting MITRE data"):
                    parts = member.filename.split('/')[1:]
                    if not parts or parts[0] not in ["enterprise-attack", "mobile-attack", "ics-attack"]:
                        continue
                    
                    target_path = os.path.join("attack-stix-data", *parts)
                    if not member.is_dir():
                        os.makedirs(os.path.dirname(target_path), exist_ok=True)
                        with open(target_path, "wb") as f: f.write(zf.read(member.filename))
            logging.info("MITRE ATT&CK data downloaded and extracted successfully.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error downloading MITRE data: {e}", exc_info=True)
            sys.exit(1)
        except Exception as e:
            logging.error(f"Failed to download or extract MITRE data: {e}", exc_info=True)
            sys.exit(1)

    def _get_mitre_data(self) -> Tuple[Dict, List]:
        """
        Loads MITRE data from STIX files, using a local cache for performance.
        If the cache is missing, it builds it by parsing the STIX JSON files.

        :return: A tuple containing two elements:
                 1. A dict mapping TTP IDs to keywords.
                 2. A list of dicts with metadata for each TTP.
        """
        if os.path.exists(MITRE_CACHE_FILE):
            logging.info(f"Loading MITRE data from cache: {MITRE_CACHE_FILE}")
            with open(MITRE_CACHE_FILE, "r", encoding="utf-8") as f: cache = json.load(f)
            return cache["keywords"], cache["metadata"]

        logging.info("MITRE cache not found. Building cache from STIX data...")
        store = MemoryStore()
        for folder in MITRE_DIRS:
            path = os.path.join(folder, f"{os.path.basename(folder)}.json")
            if not os.path.exists(path):
                logging.warning(f"STIX file not found, skipping: {path}")
                continue
            logging.info(f"Processing STIX data from: {path}")
            try:
                store.load_from_file(path)
            except Exception as e: logging.error(f"Failed to process {path}: {e}")

        logging.info("Extracting and caching MITRE ATT&CK techniques...")
        mitre_keywords, mitre_metadata = {}, []
        tech_filter = [Filter("type", "=", "attack-pattern"), Filter("revoked", "=", False)]
        for obj in store.query(tech_filter):
            if obj.get("x_mitre_deprecated", False): continue
            
            tid = next((ref.get("external_id") for ref in obj.get("external_references", []) if ref.get("source_name", "").startswith("mitre-")), None)
            if not tid: continue
            
            # Extract meaningful phrases from the description for fuzzy matching
            phrases = {s.strip().lower() for s in re.split(r'[.?!]\s+', obj.get("description", "")) if 5 <= len(s.strip()) <= 150}
            name = obj.get("name", "").strip().lower()
            if name and len(name) > 4: phrases.add(name)
            
            if phrases:
                mitre_keywords[tid] = sorted(list(phrases))
                mitre_metadata.append({
                    "id": tid,
                    "name": obj.get("name", "N/A"),
                    "tactic": next((p.get("phase_name") for p in obj.get("kill_chain_phases", [])), "unknown")
                })

        with open(MITRE_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"keywords": mitre_keywords, "metadata": mitre_metadata}, f, indent=2)
        logging.info(f"Saved {len(mitre_keywords)} MITRE techniques to cache: {MITRE_CACHE_FILE}")
        return mitre_keywords, mitre_metadata

    def _extract_indicators(self, text: str) -> Dict[str, List[str]]:
        """
        Extracts Indicators of Compromise (IoCs) from text using regex.

        :param text: The input string to analyze.
        :return: A dictionary of found indicators, keyed by type (e.g., "urls").
        """
        # This improved IPv4 regex validates octet values to reduce false positives
        # on version numbers or other similar patterns.
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        patterns = {
            "urls": re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE),
            "domains": re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b'),
            "emails": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "ipv4": re.compile(ipv4_pattern)
        }
        indicators = {name: list(set(p.findall(text))) for name, p in patterns.items()}
        
        # De-duplicate domains that are already part of a full URL
        if indicators.get("domains") and indicators.get("urls"):
            url_domains = {re.search(patterns["domains"], url).group(0) for url in indicators["urls"] if re.search(patterns["domains"], url)}
            indicators["domains"] = [d for d in indicators["domains"] if d not in url_domains]

        # Return only the indicator types that have matches
        return {k: v for k, v in indicators.items() if v}

    def _sanitize_yara_string(self, value: str) -> str:
        """
        Escapes characters in a string to be safely included in a YARA rule.
        This prevents syntax errors and potential rule injection vulnerabilities.

        :param value: The string to sanitize.
        :return: The sanitized string, safe for YARA inclusion.
        """
        value = value.replace('\\', '\\\\')
        value = value.replace('"', '\\"')
        # Hex encode non-printable or special characters to ensure rule validity
        return ''.join(c if 32 <= ord(c) < 127 else f'\\x{ord(c):02x}' for c in value)

    def _generate_yara_rule(self, result: Dict) -> str:
        """
        Generates a high-fidelity YARA rule based on the enrichment results.

        **CRITICAL AUDIT POINT:** This function includes a guardrail to prevent
        the creation of low-fidelity rules. A rule is only generated if there
        are concrete strings (from heuristic keywords or IoCs) to match on.
        This avoids creating noisy rules based only on a generic MITRE TTP name.

        :param result: The full enrichment result dictionary for an input.
        :return: A formatted YARA rule string, or an empty string if no rule is generated.
        """
        # Do not generate rules for informational or benign findings
        if result['analysis']['risk_score'] == 0:
            return ""

        # --- String Collection: Gather all high-confidence strings ---
        high_confidence_strings = []
        # 1. Add matched heuristic keywords
        for data in result['analysis']['matched_primitives'].values():
            high_confidence_strings.extend(data['matches'])
        # 2. Add all extracted IoCs
        for ind_list in result['indicators'].values():
            high_confidence_strings.extend(ind_list)
        
        # --- FIDELITY GUARDRAIL ---
        # If there are no concrete strings, do not generate a rule. This is the
        # most important step to prevent noisy rules based on fuzzy MITRE matches.
        if not high_confidence_strings:
            logging.debug(f"Skipping YARA rule for '{result['input'][:50]}...' due to lack of concrete strings.")
            return ""

        # --- Rule Construction ---
        rule_name = f"threat_heuristic_{re.sub(r'[^a-zA-Z0-9_]', '', result['input'].replace(' ', '_'))[:50]}_{int(datetime.now().timestamp())}"
        
        # Build meta section with rich context
        meta = result['analysis'].copy()
        meta["input_text"] = self._sanitize_yara_string(result["input"][:1024]) # Truncate long inputs
        if result['mitre_matches']:
            meta["mitre_ttps"] = ", ".join([m["id"] for m in result["mitre_matches"]])
        meta_fields = [f'\t\t{k} = "{self._sanitize_yara_string(str(v))}"' for k, v in meta.items() if k != 'matched_primitives']
        
        # Build strings section
        string_fields = [f'\t\t$s{i+1} = "{self._sanitize_yara_string(s)}" nocase wide ascii' for i, s in enumerate(set(high_confidence_strings))]

        # Build condition section with smarter logic
        if len(string_fields) > 2:
            condition = "2 of them"  # Requires multiple indicators for higher fidelity
        else:
            condition = "all of them"

        return f"""
rule {rule_name}
{{
    meta:
{os.linesep.join(meta_fields)}
    strings:
{os.linesep.join(string_fields)}
    condition:
        {condition}
}}
"""

    def enrich_text(self, text: str) -> Dict:
        """
        Enriches a single piece of text with a risk score, tags, IoCs, and MITRE matches.

        :param text: The input string to analyze.
        :return: A dictionary containing the full enrichment results.
        """
        # 1. Heuristic Analysis: Match against keyword primitives
        matched_primitives = {}
        for classifier in self.heuristic_classifiers:
            matches = list(set(classifier["regex"].findall(text.lower())))
            if matches:
                matched_primitives[classifier["name"]] = {"score": classifier["score"], "matches": matches}

        risk_score = sum(p["score"] for p in matched_primitives.values())
        tags = set(matched_primitives.keys())

        # 2. IoC Extraction and Scoring
        indicators = self._extract_indicators(text)
        if indicators:
            tags.add("has_indicator")
            risk_score += self.score_boosts.get("has_indicator", 5)

        # 3. MITRE ATT&CK Mapping and Scoring
        matched_tids = {tid for tid, phrases in self.mitre_keywords.items() if any(fuzz.partial_ratio(phrase, text.lower()) >= self.fuzzy_threshold for phrase in phrases)}
        
        mitre_matches = []
        if matched_tids:
            tags.add("mitre_ttp")
            risk_score += self.score_boosts.get("mitre_ttp", 6)
            for tid in sorted(list(matched_tids)):
                if (tech := next((t for t in self.mitre_metadata if t["id"] == tid), None)):
                    mitre_matches.append({"id": tech["id"], "name": tech["name"]})
                    if tech['tactic'] != 'unknown': tags.add(tech['tactic'])

        # Log inputs that had no matches for tuning purposes
        if not tags:
            with open(MISS_LOG, "a", encoding="utf-8") as f: f.write(text + "\n")

        # 4. Assemble Final Result
        result = {
            "input": text,
            "analysis": {
                "risk_score": risk_score,
                "risk_level": self.get_risk_level(risk_score),
                "tags": sorted(list(tags)),
                "matched_primitives": matched_primitives
            },
            "indicators": indicators,
            "mitre_matches": mitre_matches
        }
        result["yara_rule"] = self._generate_yara_rule(result)
        return result

    def process_batch(self, inputs: Iterable[str]) -> List[Dict]:
        """
        Processes an iterable of text inputs with a progress bar and error handling.

        :param inputs: An iterable (like a list or generator) of strings.
        :return: A list of enrichment result dictionaries.
        """
        logging.info("Starting enrichment process...")
        results = []
        for text in tqdm(inputs, desc="Enriching"):
            try:
                if not text or not isinstance(text, str): continue
                results.append(self.enrich_text(text))
            except Exception as e:
                logging.error(f"Failed to process input: '{text[:100]}...'. Error: {e}", exc_info=True)
                with open(ERROR_LOG, "a", encoding="utf-8") as f:
                    f.write(f"{text}\n")
        return results

def load_inputs(path: str) -> Generator[str, None, None]:
    """
    Loads input text from a file, yielding lines one by one to conserve memory.
    This allows the script to process very large files without crashing.

    :param path: Path to the input file (.txt, .csv, .json).
    :return: A generator that yields individual input strings.
    """
    if not os.path.exists(path):
        logging.error(f"Input file not found: {path}")
        sys.exit(1)
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            if path.lower().endswith(".csv"):
                reader = csv.reader(f)
                for row in reader:
                    if row: yield row[0]
            elif path.lower().endswith(".json"):
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        yield item.get("input", str(item)) if isinstance(item, dict) else str(item)
                elif isinstance(data, dict):
                     yield data.get("input", str(data))
            else: # Treat as .txt or any other line-delimited file
                for line in f:
                    if stripped := line.strip():
                        yield stripped
    except Exception as e:
        logging.error(f"Failed to read input file {path}: {e}", exc_info=True)
        sys.exit(1)

def save_results(results: List[Dict]):
    """
    Saves all output files for the session into a timestamped directory.

    :param results: The list of enrichment result dictionaries.
    """
    if not results:
        logging.warning("No results were generated. Skipping output file creation.")
        return
    session_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    session_path = os.path.join(OUTPUT_ROOT, f"session_{session_id}")
    os.makedirs(session_path, exist_ok=True)
    logging.info(f"Saving results to directory: {session_path}")

    # Full JSON results for deep analysis
    with open(os.path.join(session_path, "results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Consolidated IoCs with context for better analyst utility
    contextual_indicators = []
    for res in results:
        if res['indicators']:
            contextual_indicators.append({
                "input": res['input'],
                "risk_level": res['analysis']['risk_level'],
                "indicators": res['indicators']
            })
    if contextual_indicators:
        with open(os.path.join(session_path, "_all_indicators.json"), "w", encoding="utf-8") as f:
            json.dump(contextual_indicators, f, indent=2)

    # Consolidated YARA rules for easy deployment
    all_yara_rules = [res['yara_rule'] for res in results if res['yara_rule']]
    if all_yara_rules:
        with open(os.path.join(session_path, "_all_yara_rules.yara"), "w", encoding="utf-8") as f:
            f.write("\n".join(all_yara_rules))

    # High-level statistics for trend analysis
    stats = {
        "session_id": session_id,
        "total_inputs_processed": len(results),
        "risk_level_counts": dict(Counter(r["analysis"]["risk_level"] for r in results)),
        "tag_counts": dict(Counter(tag for r in results for tag in r['analysis']['tags']).most_common()),
        "top_10_mitre_techniques": [{
            "id": k[0],
            "name": k[1],
            "count": v
        } for k, v in Counter((m["id"], m.get("name")) for r in results for m in r["mitre_matches"]).most_common(10)]
    }
    with open(os.path.join(session_path, "_stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

    # Generate the human-readable summary report
    generate_summary_report(results, stats, os.path.join(session_path, "_summary_report.md"))
    logging.info("All output files saved successfully.")

def generate_summary_report(results: List[Dict], stats: Dict, path: str):
    """
    Generates a human-readable Markdown summary report for quick assessment.

    :param results: The list of enrichment result dictionaries.
    :param stats: The dictionary of summary statistics.
    :param path: The file path to save the report to.
    """
    report_lines = [f"# Threat Enrichment Report: {stats['session_id']}", ""]
    
    report_lines.append("## Executive Summary")
    report_lines.append(f"- **Total Inputs Analyzed:** {stats['total_inputs_processed']}")
    report_lines.append("- **Risk Level Distribution:**")
    risk_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for level, count in sorted(stats['risk_level_counts'].items(), key=lambda item: risk_order.index(item[0])):
        report_lines.append(f"  - {level}: {count}")
    report_lines.append("")

    report_lines.append("## High-Risk Items")
    high_risk_items = sorted([r for r in results if r['analysis']['risk_level'] in ["HIGH", "CRITICAL"]], key=lambda x: x['analysis']['risk_score'], reverse=True)
    if not high_risk_items:
        report_lines.append("No HIGH or CRITICAL risk items found.")
    else:
        # Show top 20 high-risk items for brevity
        for item in high_risk_items[:20]:
            report_lines.append(f"### Input: `{item['input'][:200]}`")
            report_lines.append(f"- **Risk Score:** {item['analysis']['risk_score']} ({item['analysis']['risk_level']})")
            report_lines.append(f"- **Tags:** `{', '.join(item['analysis']['tags'])}`")
            if item['indicators']:
                report_lines.append("- **Indicators:**")
                for ind_type, ind_list in item['indicators'].items():
                    report_lines.append(f"  - {ind_type.capitalize()}: `{', '.join(ind_list)}`")
            if item['mitre_matches']:
                report_lines.append("- **MITRE TTPs:**")
                for match in item['mitre_matches']:
                    report_lines.append(f"  - {match['id']}: {match['name']}")
            report_lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    logging.info(f"Human-readable summary report saved to: {path}")


def main():
    """
    Main execution function. Orchestrates the setup, data loading, processing,
    and saving of results.
    """
    # --- Argument Parsing with Integrated Manual ---
    manual_epilog = """
===============================================================================
 QUICK START MANUAL
===============================================================================
1. Install dependencies:
   pip install -r requirements.txt

2. Run the engine against an input file:
   python3 HunterEngine.py /path/to/your/input.txt

3. Use a custom configuration for different threat models:
   python3 HunterEngine.py emails.csv -c primitives/bec_primitives.json

4. Find all generated reports, IoCs, and YARA rules in:
   ./ClassifierBox/session_<timestamp>/
===============================================================================
"""
    parser = argparse.ArgumentParser(
        description="HunterEngine by PsypherLabs - A Heuristic Threat Enrichment Engine.",
        epilog=manual_epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("input", help="Path to the input file (.txt, .csv, .json).")
    parser.add_argument(
        "-c", "--config",
        default=DEFAULT_PRIMITIVES_CONFIG_FILE,
        help=f"Path to the configuration JSON file (default: {DEFAULT_PRIMITIVES_CONFIG_FILE})."
    )
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Suppress the startup banner and manual.'
    )
    args = parser.parse_args()

    # --- Startup Display ---
    if not args.no_banner:
        print_banner()
        print_manual_and_license()

    # Clean up logs from previous runs
    for log_file in [MISS_LOG, ERROR_LOG]:
        if os.path.exists(log_file):
            os.remove(log_file)

    # 1. Initialize and set up the engine
    engine = ThreatEnrichmentEngine(config_path=args.config)
    engine.setup_dependencies()
    
    # 2. Load inputs using the memory-efficient generator
    inputs = load_inputs(args.input)
    
    # 3. Process the batch of inputs
    results = engine.process_batch(inputs)
    
    # 4. Save all generated artifacts
    save_results(results)

if __name__ == "__main__":
    main()
