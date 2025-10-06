#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  Parsermonious Omega: The Grand Unifying Log Tool
#  Version: 1.0.0
#  Author: Gemini & Markus
#  Purpose: A feature-rich, extensible log analysis framework.
#

import argparse
import re
import os
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import math
import random

# --- ASCII Art Banner ---
BANNER = r"""
 ____                                     _
|  _ \ __ _ _ __   ___  _ __ ___  _ __ ___| | ___  ___
| |_) / _` | '_ \ / _ \| '_ ` _ \| '__/ _ \ |/ _ \/ __|
|  __/ (_| | | | | (_) | | | | | | | |  __/ |  __/\__ \
|_|   \__,_|_| |_|\___/|_| |_| |_|_|  \___|_|\___||___/
                  The Grand Unifying Log Tool
"""

# #############################################################################
# SECTION 1: LOG PROFILE DATABASE
# The heart of the multitool. Defines how to understand different log files.
# Adding a new profile here teaches the entire system a new skill.
# #############################################################################

LOG_PROFILES = {
    'truleo_tool_log': {
        'name': 'Truleo Low-Level Tool Log',
        'description': 'Logs from an automated GUI interaction tool, showing mouse and keyboard actions.',
        'detection_patterns': [r'\[INFO\] logger - action:', r'Initialized ComputerTool'],
        'parsing_rules': [
            {'type': 'action', 'regex': r'\[(?P<timestamp>.*?)\] \[INFO\] logger - action: (?P<action_type>\w+), text: (?P<text>.*?), coordinate: (?P<coords>.*)'},
            {'type': 'system', 'regex': r'\[(?P<timestamp>.*?)\] \[INFO\] logger - (?P<message>.*)'},
        ],
        'keywords': {
            'GUI_INTERACTION': {'mouse_move', 'left_click', 'type', 'coordinate', 'click'},
            'SYSTEM_STATE': {'Initialized', 'width is', 'height is', 'prevent screen lock'},
            'ERROR': {'Error', 'Failed'},
        },
        'timeline_formatter': lambda log: f"Performed '{log.get('action_type', 'N/A')}' with text '{log.get('text', 'N/A')}' at {log.get('coords', 'N/A')}." if log['log_type'] == 'action' else log.get('message', 'Unparsed Message')
    },

    'apache_access_log': {
        'name': 'Apache Web Access Log',
        'description': 'Standard log format for the Apache web server, detailing incoming HTTP requests.',
        'detection_patterns': [r'^\S+ \S+ \S+ \[.*?\] "GET|POST|HEAD', r'HTTP/1\.[01]" \d{3}'],
        'parsing_rules': [
            {'type': 'access', 'regex': r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<timestamp>.*?)\].*?"(?P<method>GET|POST|HEAD)\s(?P<url>.*?)\s.*?"\s(?P<status>\d{3})\s(?P<size>\S+)'},
        ],
        'keywords': {
            'REQUEST': {'GET', 'POST', 'HEAD', 'url'},
            'CLIENT_INFO': {'ip', 'user'},
            'RESPONSE_SUCCESS': {'200', '301', '302'},
            'RESPONSE_ERROR': {'400', '401', '403', '404', '500', '503'},
        },
        'timeline_formatter': lambda log: f"Request from {log.get('ip', 'N/A')} for '{log.get('url', 'N/A')}' returned status {log.get('status', 'N/A')}."
    },

    'nginx_access_log': {
        'name': 'Nginx Web Access Log',
        'description': 'Standard log format for the Nginx web server.',
        'detection_patterns': [r'^\S+ - \S+ \[.*?\] "GET|POST|HEAD', r'HTTP/2\.0" \d{3}'],
        'parsing_rules': [
            {'type': 'access', 'regex': r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<timestamp>.*?)\].*?"(?P<method>GET|POST|HEAD)\s(?P<url>.*?)\s.*?"\s(?P<status>\d{3})\s(?P<size>\S+)\s"(?P<referrer>.*?)"\s"(?P<user_agent>.*?)"'},
        ],
        'keywords': {
            'REQUEST': {'GET', 'POST', 'HEAD', 'url'},
            'CLIENT_INFO': {'ip', 'user', 'user_agent'},
            'RESPONSE_SUCCESS': {'200', '301', '304'},
            'RESPONSE_ERROR': {'400', '404', '499', '500', '502'},
        },
        'timeline_formatter': lambda log: f"'{log.get('method', 'N/A')} {log.get('url', 'N/A')}' from {log.get('ip', 'N/A')} ({log.get('user_agent', 'N/A')}) -> {log.get('status', 'N/A')}."
    },
    
    'linux_syslog': {
        'name': 'Linux Syslog (Standard)',
        'description': 'Generic system messages for Linux operating systems.',
        'detection_patterns': [r'^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ \S+\[\d+\]:', r'CRON\[\d+\]:'],
        'parsing_rules': [
             {'type': 'system', 'regex': r'^(?P<timestamp>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) (?P<process>\S+?)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)'},
        ],
        'keywords': {
            'SYSTEM_DAEMON': {'cron', 'systemd', 'sshd', 'kernel'},
            'AUTHENTICATION': {'session opened', 'session closed', 'authentication failure', 'pam_unix'},
            'ERROR': {'error', 'failed', 'cannot', 'unable'},
        },
        'timeline_formatter': lambda log: f"[{log.get('process', 'N/A')}({log.get('pid', 'N/A')})] {log.get('message', 'N/A')} on {log.get('hostname', 'N/A')}."
    },

    'windows_event_log_csv': {
        'name': 'Windows Event Log (CSV)',
        'description': 'Exported logs from Windows Event Viewer in CSV format.',
        'detection_patterns': [r'"Level","Date and Time","Source","Event ID",', r'System,Microsoft-Windows-'],
        'parsing_rules': [
            {'type': 'event', 'regex': r'"(?P<level>[^"]+)","(?P<timestamp>[^"]+)","(?P<source>[^"]+)","(?P<event_id>[^"]+)","(?P<task_category>[^"]+)","(?P<message>.*)"'},
        ],
        'keywords': {
            'SEVERITY_HIGH': {'Critical', 'Error'},
            'SEVERITY_MEDIUM': {'Warning'},
            'SEVERITY_INFO': {'Information'},
            'SECURITY': {'Audit Success', 'Audit Failure', 'Security'},
            'SYSTEM': {'Kernel-Power', 'Service Control Manager'},
        },
        'timeline_formatter': lambda log: f"{log.get('level', 'N/A')} from {log.get('source', 'N/A')} (ID {log.get('event_id', 'N/A')}): {log.get('message', 'N/A')[:100]}..."
    },
    
    'json_log': {
        'name': 'JSON Log Format',
        'description': 'Logs where each line is a self-contained JSON object.',
        'detection_patterns': [r'^{.*"level":.*}$', r'^{.*"timestamp":.*}$'],
        'parsing_rules': [
            {'type': 'json_entry', 'is_json': True},
        ],
        'keywords': { # Keywords are generic, specific analysis would depend on JSON structure
            'SEVERITY': {'level', 'severity'},
            'METADATA': {'timestamp', 'hostname', 'service', 'module'},
            'ERROR': {'error', 'exception', 'traceback'},
        },
        'timeline_formatter': lambda log: log.get('message', next((v for k, v in log.items() if k not in ['timestamp', 'level']), 'JSON entry'))
    },

    'python_traceback': {
        'name': 'Python Application Traceback',
        'description': 'Standard error output from Python applications.',
        'detection_patterns': [r'Traceback \(most recent call last\):', r'File ".*?", line \d+, in'],
        'parsing_rules': [
            {'type': 'error_header', 'regex': r'^(?P<traceback>Traceback \(most recent call last\):)'},
            {'type': 'file_path', 'regex': r'^\s+File "(?P<file_path>.*?)", line (?P<line_number>\d+), in (?P<function>.*)'},
            {'type': 'error_message', 'regex': r'^(?P<error_type>\w+Error): (?P<error_message>.*)'},
        ],
        'keywords': {
            'ERROR_CONTEXT': {'Traceback', 'File', 'line'},
            'ERROR_TYPE': {'ValueError', 'TypeError', 'KeyError', 'FileNotFoundError', 'Exception'},
        },
        'timeline_formatter': lambda log: f"Error '{log.get('error_type')}' in '{log.get('file_path')}' at line {log.get('line_number')}." if log.get('error_type') else 'Traceback context line.'
    },
    
    'cisco_asa_firewall': {
        'name': 'Cisco ASA Firewall Log',
        'description': 'Logs from a Cisco ASA series firewall, typically via syslog.',
        'detection_patterns': [r'%ASA-\d-\d+:', r'Built connection', r'Teardown TCP connection'],
        'parsing_rules': [
            {'type': 'connection', 'regex': r'%ASA-\d-(?P<event_code>\d+): (?P<action>Built|Teardown) (?P<protocol>\S+) connection \d+ for (?P<direction>inbound|outbound) .*? to (?P<dest_ip>\S+)/\d+.* from (?P<src_ip>\S+)/\d+'},
            {'type': 'access', 'regex': r'%ASA-\d-(?P<event_code>\d+): (?P<action>Deny|Permit) (?P<protocol>\S+) src .*?:(?P<src_ip>\S+)/\d+ dst .*?:(?P<dest_ip>\S+)/\d+'},
        ],
        'keywords': {
            'CONNECTION_MGMT': {'Built', 'Teardown', 'connection'},
            'ACCESS_CONTROL': {'Deny', 'Permit', 'access-list'},
            'IP_INFO': {'src_ip', 'dest_ip'},
        },
        'timeline_formatter': lambda log: f"{log.get('action', 'N/A')} {log.get('protocol', 'N/A')} from {log.get('src_ip', 'N/A')} to {log.get('dest_ip', 'N/A')} (Code: {log.get('event_code', 'N/A')})."
    },

    'git_log': {
        'name': 'Git Log Output',
        'description': 'Standard output from the `git log` command.',
        'detection_patterns': [r'^commit [0-9a-f]{40}', r'^Author:', r'^Date:'],
        'parsing_rules': [
            {'type': 'commit', 'regex': r'^commit (?P<commit_hash>[0-9a-f]{40})'},
            {'type': 'author', 'regex': r'^Author: (?P<author>.*)'},
            {'type': 'date', 'regex': r'^Date:\s+(?P<date>.*)'},
            {'type': 'message', 'regex': r'^\s{4}(?P<message>.*)'},
        ],
        'keywords': {
            'METADATA': {'commit', 'Author', 'Date'},
            'ACTIONS': {'fix', 'feat', 'refactor', 'docs', 'style', 'test', 'chore', 'merge'},
        },
        'timeline_formatter': lambda log: f"Commit {log.get('commit_hash', 'N/A')[:7]} by {log.get('author', 'N/A')}: {log.get('message', 'No message')}."
    },
    
    'generic': { # Fallback profile
        'name': 'Generic Text File',
        'description': 'A generic profile for unrecognized text files.',
        'detection_patterns': [],
        'parsing_rules': [
            {'type': 'generic', 'regex': r'^(?P<line_content>.*)'},
        ],
        'keywords': {},
        'timeline_formatter': lambda log: log.get('line_content', 'Generic Line')
    }
}


# #############################################################################
# SECTION 2: THE PARSERMONIOUS CORE CLASS
# Orchestrates the entire analysis process from file loading to report generation.
# #############################################################################

class Parsermonious:
    """The main orchestrator for the log analysis multitool."""

    def __init__(self, filepath):
        """
        Initializes the analysis process for a given log file.
        
        Args:
            filepath (str): The path to the log file.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"The file '{filepath}' was not found.")
        
        self.filepath = filepath
        self.basename = os.path.splitext(self.filepath)[0]
        self.lines = self._load_file()
        self.total_lines = len(self.lines)
        self.profile_key, self.profile = self._detect_profile()
        self.parsed_logs = self._parse_logs()

    def _load_file(self):
        """Loads the log file, attempting to handle various encodings."""
        encodings_to_try = ['utf-8-sig', 'latin-1', 'utf-16']
        for enc in encodings_to_try:
            try:
                with open(self.filepath, 'r', encoding=enc) as f:
                    return [line.strip() for line in f if line.strip()]
            except UnicodeDecodeError:
                continue
        raise ValueError("Could not decode the file with common encodings.")

    def _detect_profile(self):
        """
        Scores and selects the best log profile for the file content.
        
        Returns:
            tuple: A tuple containing the key and dictionary of the best-matching profile.
        """
        scores = Counter()
        for key, profile in LOG_PROFILES.items():
            if not profile.get('detection_patterns'):
                continue
            for pattern in profile['detection_patterns']:
                try:
                    # Score based on how many of the first 200 lines match
                    scores[key] += sum(1 for line in self.lines[:200] if re.search(pattern, line))
                except re.error:
                    print(f"Warning: Invalid regex in profile '{key}': {pattern}")
        
        if not scores:
            return 'generic', LOG_PROFILES['generic']
            
        best_profile_key = scores.most_common(1)[0][0]
        return best_profile_key, LOG_PROFILES[best_profile_key]

    def _parse_logs(self):
        """
        Parses each line of the log file according to the detected profile's rules.
        
        Returns:
            list: A list of dictionaries, where each dictionary represents a parsed log entry.
        """
        parsed = []
        rules = self.profile.get('parsing_rules', [])
        
        for line_num, line in enumerate(self.lines):
            log_entry = {'original_line': line, 'line_number': line_num + 1}
            
            matched = False
            for rule in rules:
                if rule.get('is_json', False):
                    try:
                        json_data = json.loads(line)
                        log_entry.update(json_data)
                        log_entry['log_type'] = rule.get('type', 'json_entry')
                        matched = True
                        break
                    except json.JSONDecodeError:
                        continue
                
                match = re.search(rule['regex'], line)
                if match:
                    log_entry.update(match.groupdict())
                    log_entry['log_type'] = rule.get('type', 'unknown')
                    matched = True
                    break
            
            if not matched:
                log_entry['log_type'] = 'unmatched'
                log_entry['message'] = line

            parsed.append(log_entry)
        return parsed

    def run_full_analysis(self):
        """
        Executes all analysis modules and generates the final reports.
        """
        print(BANNER)
        print(f"Analyzing '{os.path.basename(self.filepath)}' ({self.total_lines:,} lines)...")
        print(f"-> Detected Profile: '{self.profile['name']}'")

        analyzer = LogAnalyzer(self.parsed_logs, self.profile)
        analysis_results = analyzer.run_all_analyses()
        
        reporter = ReportGenerator(self.basename, analysis_results, self.parsed_logs)
        reporter.generate_html_report()
        reporter.generate_text_report()
        
        print("\nAnalysis complete. Generated HTML and Text reports.")


# #############################################################################
# SECTION 3: THE LOG ANALYZER CLASS
# Contains all the "bells and whistles" for deep log analysis.
# #############################################################################

class LogAnalyzer:
    """Performs various analytical tasks on parsed log data."""

    def __init__(self, parsed_logs, profile):
        self.logs = parsed_logs
        self.profile = profile
        self.results = {'profile_name': profile['name']}

    def run_all_analyses(self):
        """Runs all available analysis methods and returns the results."""
        print("-> Running statistical analysis...")
        self.results['stats'] = self._calculate_stats()
        
        print("-> Analyzing errors and warnings...")
        self.results['errors'] = self._analyze_errors()
        
        print("-> Performing contextual analysis...")
        self.results['context'] = self._analyze_context()
        
        print("-> Identifying top events...")
        self.results['top_events'] = self._find_top_events()
        
        print("-> Building relationship graph...")
        self.results['relationships'] = self._build_relationship_graph()

        print("-> Detecting anomalies...")
        self.results['anomalies'] = self._detect_anomalies()
        
        print("-> Geolocating IPs (mock)...")
        self.results['geoip'] = self._geolocate_ips()

        return self.results

    def _calculate_stats(self):
        """Calculates basic statistics about the log file."""
        stats = {}
        stats['total_events'] = len(self.logs)
        
        # Generic timestamp parsing
        timestamps = []
        for log in self.logs:
            ts_str = log.get('timestamp')
            if not ts_str: continue
            try:
                # Attempt multiple common formats
                if re.match(r'\d{4}-\d{2}-\d{2}', ts_str):
                    timestamps.append(datetime.strptime(ts_str.split(',')[0], '%Y-%m-%d %H:%M:%S'))
                elif re.match(r'\d{2}/\w{3}/\d{4}', ts_str): # Apache/Nginx
                    timestamps.append(datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S %z'))
                elif re.match(r'\w{3}\s+\d{1,2}', ts_str): # Syslog
                    # Syslog doesn't have a year, assume current year
                    ts = datetime.strptime(ts_str, '%b %d %H:%M:%S')
                    timestamps.append(ts.replace(year=datetime.now().year))

            except (ValueError, TypeError):
                continue

        if timestamps:
            stats['time_span_minutes'] = (max(timestamps) - min(timestamps)).total_seconds() / 60
            if stats['time_span_minutes'] > 0:
                stats['events_per_minute'] = stats['total_events'] / stats['time_span_minutes']
        return stats
    
    def _analyze_errors(self):
        """Finds and categorizes log entries that indicate errors."""
        error_keywords = self.profile.get('keywords', {}).get('ERROR', set()) | \
                         self.profile.get('keywords', {}).get('RESPONSE_ERROR', set())
        
        error_logs = []
        for log in self.logs:
            line = log['original_line'].lower()
            if any(kw.lower() in line for kw in error_keywords):
                error_logs.append(log)
        return {'count': len(error_logs), 'top_errors': Counter(log['original_line'] for log in error_logs).most_common(5)}
        
    def _analyze_context(self):
        """Uses the profile's keyword matrix to determine the log's purpose."""
        topic_counts = Counter()
        keyword_map = self.profile.get('keywords', {})
        if not keyword_map:
            return {}

        text_blob = " ".join(log['original_line'] for log in self.logs).lower()
        for category, keywords in keyword_map.items():
            topic_counts[category] = sum(text_blob.count(kw.lower()) for kw in keywords)
        
        total_keywords = sum(topic_counts.values())
        if not total_keywords:
            return {}
            
        return {topic: (count / total_keywords) * 100 for topic, count in topic_counts.items()}

    def _find_top_events(self, n=10):
        """Finds the most frequently occurring types of events."""
        def templatize(log):
            msg = log.get('message', log['original_line'])
            msg = re.sub(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 'IP_ADDR', msg)
            msg = re.sub(r'\d{5,}', 'LONG_NUM', msg)
            msg = re.sub(r'0x[0-9a-fA-F]+', 'HEX_ADDR', msg)
            return msg

        return Counter(templatize(log) for log in self.logs).most_common(n)

    def _build_relationship_graph(self, window_size=5):
        """
        Builds a co-occurrence matrix for keywords to find relationships.
        
        Returns:
            dict: A dictionary of related keyword pairs and their scores.
        """
        graph = defaultdict(Counter)
        keywords_flat = [kw.lower() for kws in self.profile.get('keywords', {}).values() for kw in kws]
        
        for i in range(len(self.logs) - window_size):
            window_text = " ".join(self.logs[j]['original_line'].lower() for j in range(i, i + window_size))
            
            present_keywords = [kw for kw in keywords_flat if kw in window_text]
            
            for j in range(len(present_keywords)):
                for k in range(j + 1, len(present_keywords)):
                    kw1, kw2 = sorted((present_keywords[j], present_keywords[k]))
                    if kw1 != kw2:
                        graph[kw1][kw2] += 1
                        
        top_relations = []
        for kw1, others in graph.items():
            for kw2, score in others.items():
                top_relations.append(((kw1, kw2), score))
        
        return sorted(top_relations, key=lambda x: x[1], reverse=True)[:10]

    def _detect_anomalies(self):
        """Detects anomalies based on event frequency spikes."""
        anomalies = []
        timestamps = []
        for log in self.logs:
            ts_str = log.get('timestamp')
            if not ts_str: continue
            try:
                if re.match(r'\d{4}-\d{2}-\d{2}', ts_str):
                    timestamps.append(datetime.strptime(ts_str.split(',')[0], '%Y-%m-%d %H:%M:%S'))
            except ValueError:
                continue

        if len(timestamps) < 10: return []

        events_per_minute = Counter(t.strftime('%Y-%m-%d %H:%M') for t in timestamps)
        
        counts = list(events_per_minute.values())
        if not counts: return []
        
        mean = sum(counts) / len(counts)
        std_dev = math.sqrt(sum((x - mean) ** 2 for x in counts) / len(counts))

        threshold = mean + (2 * std_dev)
        
        for minute, count in events_per_minute.items():
            if count > threshold:
                anomaly_desc = f"High activity spike: {count} events at {minute} (mean is {mean:.1f}, threshold is {threshold:.1f})."
                anomalies.append(anomaly_desc)
        return anomalies

    def _geolocate_ips(self):
        """Finds IPs and performs a mock geolocation lookup."""
        ips = set()
        for log in self.logs:
            # Find IPs in common fields or the whole line
            ip_str = log.get('ip', '') + log.get('src_ip', '') + log.get('dest_ip', '') + log['original_line']
            found_ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ip_str)
            # Filter out private IPs
            for ip in found_ips:
                if not ip.startswith(('10.', '192.168.', '172.16.')):
                    ips.add(ip)
        
        # Mock API call
        locations = {}
        for ip in list(ips)[:20]: # Limit to 20 IPs to not clutter the report
            mock_countries = ['USA', 'Germany', 'Brazil', 'Russia', 'China', 'Australia', 'Canada']
            mock_cities = ['New York', 'Berlin', 'Sao Paulo', 'Moscow', 'Beijing', 'Sydney', 'Toronto']
            locations[ip] = f"{random.choice(mock_cities)}, {random.choice(mock_countries)}"
        
        return {'count': len(ips), 'locations': locations}


# #############################################################################
# SECTION 4: THE REPORT GENERATOR
# Creates beautiful and informative output files from the analysis results.
# #############################################################################

class ReportGenerator:
    """Generates reports in various formats (HTML, Text)."""
    
    def __init__(self, base_filename, analysis_results, parsed_logs):
        self.base_filename = base_filename
        self.results = analysis_results
        self.logs = parsed_logs
        self.profile = LOG_PROFILES.get(analysis_results.get('profile_key', 'generic'), LOG_PROFILES['generic'])

    def generate_text_report(self):
        """Generates a comprehensive plain text report."""
        path = self.base_filename + "_analysis.txt"
        with open(path, 'w', encoding='utf-8') as f:
            f.write(BANNER + "\n")
            f.write("="*60 + "\n")
            f.write("  Analysis Report\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Profile: {self.results['profile_name']}\n")
            
            # Stats
            stats = self.results.get('stats', {})
            f.write("\n---[ Statistics ]---\n")
            for key, val in stats.items():
                f.write(f"- {key.replace('_', ' ').title()}: {val:.2f if isinstance(val, float) else val:,}\n")

            # Context
            context = self.results.get('context', {})
            f.write("\n---[ Context Analysis (What is this log about?) ]---\n")
            for topic, pct in sorted(context.items(), key=lambda x: x[1], reverse=True):
                f.write(f"- {topic.replace('_', ' ').title()}: {pct:.1f}%\n")

            # Errors
            errors = self.results.get('errors', {})
            f.write(f"\n---[ Error Analysis ]---\n")
            f.write(f"Total Errors Found: {errors.get('count', 0)}\n")
            f.write("Top 5 Error Messages:\n")
            for msg, count in errors.get('top_errors', []):
                f.write(f"  (x{count}) {msg[:100]}...\n")

            # Top Events
            f.write("\n---[ Top 10 Most Common Events ]---\n")
            for msg, count in self.results.get('top_events', []):
                 f.write(f"  (x{count}) {msg[:100]}...\n")
            
            # Relationships
            f.write("\n---[ Top 10 Keyword Relationships ]---\n")
            for (kw1, kw2), score in self.results.get('relationships', []):
                f.write(f"- '{kw1}' <-> '{kw2}' (Score: {score})\n")

            # Anomalies
            f.write("\n---[ Detected Anomalies ]---\n")
            anomalies = self.results.get('anomalies', [])
            if anomalies:
                for anomaly in anomalies:
                    f.write(f"- {anomaly}\n")
            else:
                f.write("No significant anomalies detected.\n")
            
            # GeoIP
            geoip = self.results.get('geoip', {})
            f.write("\n---[ GeoIP Lookups (Mock) ]---\n")
            f.write(f"Unique Public IPs Found: {geoip.get('count', 0)}\n")
            for ip, loc in geoip.get('locations', {}).items():
                 f.write(f"- {ip}: {loc}\n")

    def generate_html_report(self):
        """Generates a single, self-contained interactive HTML report."""
        path = self.base_filename + "_analysis.html"
        
        # Data preparation for charts
        context_data = self.results.get('context', {})
        context_labels = json.dumps(list(context_data.keys()))
        context_values = json.dumps(list(context_data.values()))
        
        top_events = self.results.get('top_events', [])
        top_events_labels = json.dumps([f"{evt[:30]}..." for evt, count in top_events])
        top_events_values = json.dumps([count for evt, count in top_events])

        # HTML and CSS Structure
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Parsermonious Report: {os.path.basename(self.base_filename)}</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background-color: #f8f9fa; color: #343a40; }}
                .container {{ max-width: 1200px; margin: auto; padding: 20px; }}
                .header {{ background-color: #343a40; color: white; padding: 40px; text-align: center; }}
                .header h1 {{ margin: 0; font-size: 2.5em; }}
                .header p {{ margin-top: 5px; font-size: 1.2em; color: #adb5bd; }}
                .grid-container {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; margin-top: 20px; }}
                .card {{ background: white; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); padding: 20px; }}
                .card.full-width {{ grid-column: 1 / -1; }}
                .card h2 {{ margin-top: 0; border-bottom: 2px solid #e9ecef; padding-bottom: 10px; color: #495057;}}
                .card pre, .card ul {{ margin: 0; padding: 0; list-style-type: none; }}
                .card li {{ padding: 8px 0; border-bottom: 1px solid #f1f3f5; }}
                .card li:last-child {{ border-bottom: none; }}
                .stat-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; text-align: center; }}
                .stat-item h3 {{ margin: 0 0 5px 0; font-size: 2em; color: #007bff; }}
                .stat-item p {{ margin: 0; color: #6c757d; }}
                .table-container {{ max-height: 400px; overflow-y: auto; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #dee2e6; }}
                th {{ background-color: #f8f9fa; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Parsermonious Omega</h1>
                <p>Analysis Report for {os.path.basename(self.base_filename)}</p>
            </div>
            <div class="container">
                <div class="grid-container">
                    <div class="card">
                        <h2>Log Profile</h2>
                        <p><strong>Detected Type:</strong> {self.results['profile_name']}</p>
                        <p><em>{self.profile.get('description', '')}</em></p>
                    </div>
                    <div class="card">
                        <h2>Overall Statistics</h2>
                        <div class="stat-grid">
                            <div class="stat-item">
                                <h3>{self.results.get('stats', {}).get('total_events', 0):,}</h3>
                                <p>Total Events</p>
                            </div>
                            <div class="stat-item">
                                <h3>{self.results.get('errors', {}).get('count', 0):,}</h3>
                                <p>Errors Found</p>
                            </div>
                            <div class="stat-item">
                                <h3>{self.results.get('stats', {}).get('events_per_minute', 0):.1f}</h3>
                                <p>Events / Minute</p>
                            </div>
                            <div class="stat-item">
                                <h3>{self.results.get('geoip', {}).get('count', 0):,}</h3>
                                <p>Unique Public IPs</p>
                            </div>
                        </div>
                    </div>
                    <div class="card full-width">
                        <h2>Contextual Analysis</h2>
                        <canvas id="contextChart"></canvas>
                    </div>
                    <div class="card full-width">
                        <h2>Top 10 Most Common Events</h2>
                        <canvas id="topEventsChart"></canvas>
                    </div>
                    <div class="card">
                        <h2>Top Keyword Relationships</h2>
                        <ul>{''.join(f"<li><strong>'{kw1}'</strong> &harr; <strong>'{kw2}'</strong> (Score: {score})</li>" for (kw1, kw2), score in self.results.get('relationships', []))}</ul>
                    </div>
                    <div class="card">
                        <h2>Detected Anomalies</h2>
                        <ul>{''.join(f"<li>{anomaly}</li>" for anomaly in self.results.get('anomalies', [])) or "<li>No significant anomalies found.</li>"}</ul>
                    </div>
                    <div class="card full-width">
                        <h2>Timeline of Events</h2>
                        <div class="table-container">
                            <table>
                                <thead><tr><th>Line</th><th>Event Description</th></tr></thead>
                                <tbody>
                                    {''.join(f"<tr><td>{log['line_number']}</td><td>{self.profile['timeline_formatter'](log)}</td></tr>" for log in self.logs[:200])}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            <script>
                new Chart(document.getElementById('contextChart'), {{
                    type: 'pie',
                    data: {{
                        labels: {context_labels},
                        datasets: [{{
                            label: 'Context Distribution',
                            data: {context_values},
                            backgroundColor: ['#007bff', '#28a745', '#dc3545', '#ffc107', '#17a2b8', '#6c757d'],
                        }}]
                    }},
                    options: {{ responsive: true, plugins: {{ legend: {{ position: 'top' }} }} }}
                }});
                new Chart(document.getElementById('topEventsChart'), {{
                    type: 'bar',
                    data: {{
                        labels: {top_events_labels},
                        datasets: [{{
                            label: '# of Occurrences',
                            data: {top_events_values},
                            backgroundColor: '#007bff',
                        }}]
                    }},
                    options: {{ responsive: true, indexAxis: 'y' }}
                }});
            </script>
        </body>
        </html>
        """
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
            
# #############################################################################
# SECTION 5: COMMAND-LINE INTERFACE
# #############################################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=BANNER,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("logfile", help="Path to the log file to be analyzed.")
    args = parser.parse_args()
    
    try:
        omega_tool = Parsermonious(args.logfile)
        omega_tool.run_full_analysis()
    except Exception as e:
        print(f"\n--- [ CRITICAL ERROR ] ---")
        print(f"An error occurred: {e}")
        print("Please check the file path and ensure it is a readable text file.")

