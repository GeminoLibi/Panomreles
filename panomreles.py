#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  panomreles Titan: The Grand Unifying Log Tool
#  Version: 1.0.0
#  Author: Gemini & GeminoLibi
#  Purpose: A log processing and intelligence platform that generates a full, structured analysis package.
#
#  --- [ How to use as a Plugin for Project Revelare ] ---
#
#  This script is designed to be dual-use. You can run it from the command line
#  as a standalone tool, or you can import its `analyze` function into your
#  own Python projects.
#
#  Example Usage in another Python script:
#
#  from panomreles import analyze
#
#  # Define a configuration to control the output
#  plugin_config = {
#      'custom_output_dir': '/path/to/revelare/analysis_cache',
#      'generate_html_report': True,
#      'generate_text_report': False,
#      'generate_briefing': True,
#      'export_raw_data': True,
#  }
#
#  try:
#      # Call the analysis engine
#      analysis_results = analyze('path/to/logfile.log', config=plugin_config)
#
#      # Now you have the structured data for your own application
#      print("Analysis complete.")
#      print(f"Total events found: {analysis_results.get('stats', {}).get('total_events')}")
#      if analysis_results.get('threat_intel', {}).get('watchlist_hits'):
#          print("Threats were detected!")
#
#  except FileNotFoundError:
#      print("Log file not found.")
#  except Exception as e:
#      print(f"An error occurred during analysis: {e}")
#
# -----------------------------------------------------------------------------

import argparse
import re
import os
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import math
import shutil

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
# This library has been massively expanded.
# #############################################################################

LOG_PROFILES = {
    # --- Agent & Automation Logs ---
    'anthropic_tool_log': {
        'name': 'Anthropic Agent Low-Level Tool Log',
        'description': 'Logs from a Claude agent interacting with a tool, showing GUI actions and agent-tool communication.',
        'detection_patterns': [r'\[INFO\] logger - action:', r'<anthropic_agent\.'],
        'parsing_rules': [
            {'type': 'action', 'regex': r'\[(?P<timestamp>.*?)\] \[INFO\] logger - action: (?P<action_type>\w+), text: (?P<text>.*?), coordinate: (?P<coords>.*)'},
            {'type': 'agent_comm', 'regex': r'\[(?P<timestamp>.*?)\] \[INFO\] logger - .*<anthropic_agent\.(?P<agent_class>\w+)\._dict_to_beta_message\.<locals>\.BetaMessageObject object at (?P<mem_addr>0x[0-9a-fA-F]+)>'},
            {'type': 'user_prompt', 'regex': r'chatbot_state: \[\(\'(?P<prompt>_UQN\|\$.*?)\''},
            {'type': 'system', 'regex': r'\[(?P<timestamp>.*?)\] \[INFO\] logger - (?P<message>.*)'},
        ],
        'keywords': {
            'GUI_INTERACTION': {'mouse_move', 'left_click', 'type', 'coordinate', 'click', 'screenshot'},
            'SYSTEM_STATE': {'Initialized', 'width is', 'height is', 'prevent screen lock'},
            'AGENT_METADATA': {'anthropic_agent', 'BetaMessageObject', 'chatbot_output_callback'},
            'AGENT_THOUGHT': {'thinking', 'tool_code'},
            'ERROR': {'Error', 'Failed', 'returned no result', 'exception'},
        },
        'thematic_grouping': {
            'errors': lambda log: any(kw in log['original_line'].lower() for kw in ['error', 'failed']),
            'gui_mouse': lambda log: log.get('action_type') in ['mouse_move', 'left_click'],
            'gui_keyboard': lambda log: log.get('action_type') == 'type',
            'gui_vision': lambda log: 'screenshot' in log.get('message', '').lower(),
            'agent_communications': lambda log: log.get('log_type') == 'agent_comm',
            'agent_thoughts': lambda log: 'thinking' in log.get('message', '').lower(),
            'user_prompts': lambda log: log.get('log_type') == 'user_prompt',
            'system_events': lambda log: log.get('log_type') == 'system' and log.get('action_type') is None,
        },
        'session_field': None,
        'timestamp_format': '%Y-%m-%d %H:%M:%S',
        'timeline_formatter': lambda log: f"Performed '{log.get('action_type', 'N/A')}' with text '{log.get('text', 'N/A')}' at {log.get('coords', 'N/A')}." if log.get('log_type') == 'action' else log.get('message', 'Unparsed Message')
    },

    # --- Web Server Logs ---
    'apache_access_log': {
        'name': 'Apache Web Access Log',
        'description': 'Standard log format for the Apache web server, detailing incoming HTTP requests.',
        'detection_patterns': [r'^\S+ \S+ \S+ \[.*?\] "GET|POST|HEAD', r'HTTP/1\.[01]" \d{3}'],
        'parsing_rules': [{'type': 'access', 'regex': r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<timestamp>.*?)\].*?"(?P<method>GET|POST|HEAD)\s(?P<url>.*?)\s.*?"\s(?P<status>\d{3})\s(?P<size>\S+)'}],
        'keywords': {'REQUEST': {'GET', 'POST', 'HEAD'}, 'CLIENT_INFO': {'ip', 'user'}, 'RESPONSE_SUCCESS': {'200', '301'}, 'RESPONSE_ERROR': {'404', '500', '403'}},
        'thematic_grouping': {
            'errors_4xx': lambda log: log.get('status', '').startswith('4'),
            'errors_5xx': lambda log: log.get('status', '').startswith('5'),
            'successful_requests': lambda log: log.get('status', '').startswith('2'),
            'bot_traffic': lambda log: any(bot in log.get('user_agent', '').lower() for bot in ['bot', 'spider', 'crawler']),
        },
        'session_field': 'ip', 'timestamp_format': '%d/%b/%Y:%H:%M:%S %z', 'timeline_formatter': lambda log: f"Request from {log.get('ip', 'N/A')} for '{log.get('url', 'N/A')}' -> {log.get('status', 'N/A')}."
    },
    'nginx_access_log': {
        'name': 'Nginx Web Access Log',
        'description': 'Standard log format for the Nginx web server.',
        'detection_patterns': [r'^\S+ - \S+ \[.*?\] "GET|POST|HEAD', r'HTTP/2\.0" \d{3}'],
        'parsing_rules': [{'type': 'access', 'regex': r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<timestamp>.*?)\].*?"(?P<method>GET|POST|HEAD)\s(?P<url>.*?)\s.*?"\s(?P<status>\d{3})\s(?P<size>\S+)\s"(?P<referrer>.*?)"\s"(?P<user_agent>.*?)"'}],
        'keywords': {'REQUEST': {'GET', 'POST'}, 'CLIENT_INFO': {'ip', 'user_agent'}, 'RESPONSE_ERROR': {'404', '499', '502'}},
        'thematic_grouping': {
            'errors_4xx': lambda log: log.get('status', '').startswith('4'),
            'errors_5xx': lambda log: log.get('status', '').startswith('5'),
        },
        'session_field': 'ip', 'timestamp_format': '%d/%b/%Y:%H:%M:%S %z', 'timeline_formatter': lambda log: f"'{log.get('method')} {log.get('url')}' from {log.get('ip')} -> {log.get('status')}."
    },
    'iis_log': {
        'name': 'Microsoft IIS Log (W3C)',
        'description': 'Logs from Microsoft\'s Internet Information Services web server.',
        'detection_patterns': [r'^#Software: Microsoft Internet Information Services', r'^#Fields: date time s-ip cs-method'],
        'parsing_rules': [{'type': 'access', 'regex': r'^(?P<date>\S+)\s(?P<time>\S+)\s(?P<s_ip>\S+)\s(?P<cs_method>\S+)\s(?P<cs_uri_stem>\S+)\s(?P<cs_uri_query>\S+)\s(?P<s_port>\d+)\s(?P<cs_username>\S+)\s(?P<c_ip>\S+)\s(?P<cs_user_agent>\S+)\s(?P<sc_status>\d+)'}],
        'keywords': {'REQUEST': {'GET', 'POST'}, 'CLIENT_INFO': {'c_ip', 'cs_user_agent'}, 'RESPONSE_ERROR': {'404', '500'}},
        'thematic_grouping': {'errors': lambda log: log.get('sc_status', '').startswith(('4', '5'))},
        'session_field': 'c_ip', 'timestamp_format': '%Y-%m-%d %H:%M:%S', # Note: requires combining date and time fields
        'timeline_formatter': lambda log: f"{log.get('cs_method')} request for {log.get('cs_uri_stem')} from {log.get('c_ip')} -> {log.get('sc_status')}."
    },

    # --- System & Security Logs ---
    'linux_syslog': {
        'name': 'Linux Syslog (Standard)',
        'description': 'Generic system messages for Linux operating systems.',
        'detection_patterns': [r'^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ \S+\[\d+\]:', r'CRON\[\d+\]:'],
        'parsing_rules': [{'type': 'system', 'regex': r'^(?P<timestamp>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) (?P<process>\S+?)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)'}],
        'keywords': {'SYSTEM_DAEMON': {'cron', 'systemd', 'sshd'}, 'AUTHENTICATION': {'session opened', 'authentication failure'}, 'ERROR': {'error', 'failed'}},
        'thematic_grouping': {
            'auth_events': lambda log: 'session' in log.get('message', '').lower() or 'authentication' in log.get('message', '').lower(),
            'cron_jobs': lambda log: 'cron' in log.get('process', '').lower(),
        },
        'session_field': 'process', 'timestamp_format': '%b %d %H:%M:%S',
        'timeline_formatter': lambda log: f"[{log.get('process')}({log.get('pid')})] {log.get('message')} on {log.get('hostname')}."
    },
    'windows_event_log_csv': {
        'name': 'Windows Event Log (CSV)',
        'description': 'Exported logs from Windows Event Viewer in CSV format.',
        'detection_patterns': [r'"Level","Date and Time","Source","Event ID",', r'System,Microsoft-Windows-'],
        'parsing_rules': [{'type': 'event', 'regex': r'"(?P<level>[^"]+)","(?P<timestamp>[^"]+)","(?P<source>[^"]+)","(?P<event_id>[^"]+)","(?P<task_category>[^"]+)","(?P<message>.*)"'}],
        'keywords': {'SEVERITY_HIGH': {'Critical', 'Error'}, 'SECURITY': {'Audit Success', 'Audit Failure'}, 'SYSTEM': {'Kernel-Power'}},
        'thematic_grouping': {'critical_errors': lambda log: log.get('level') == 'Critical'},
        'session_field': 'Source', 'timestamp_format': 'iso', # Special case for ISO 8601
        'timeline_formatter': lambda log: f"{log.get('level')} from {log.get('source')} (ID {log.get('event_id')}): {log.get('message', '')[:100]}..."
    },
    'sshd_log': {
        'name': 'OpenSSH Server Log',
        'description': 'Authentication and session logs from the OpenSSH daemon.',
        'detection_patterns': [r'sshd\[\d+\]: Accepted password for', r'sshd\[\d+\]: Failed password for'],
        'parsing_rules': [{'type': 'auth', 'regex': r'^(?P<timestamp>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: (?P<message>(?:Accepted|Failed|Invalid user) .* from (?P<ip>\S+))'}],
        'keywords': {'AUTH_SUCCESS': {'Accepted password', 'session opened'}, 'AUTH_FAILURE': {'Failed password', 'Invalid user'}},
        'thematic_grouping': {
            'successful_logins': lambda log: 'Accepted' in log.get('message', ''),
            'failed_logins': lambda log: 'Failed' in log.get('message', ''),
        },
        'session_field': 'ip', 'timestamp_format': '%b %d %H:%M:%S',
        'timeline_formatter': lambda log: f"SSHD event: {log.get('message')}."
    },
    'fail2ban_log': {
        'name': 'Fail2Ban Log',
        'description': 'Logs from the Fail2Ban intrusion prevention software.',
        'detection_patterns': [r'fail2ban\.actions\s+\[\d+\]:', r'NOTICE\s+\[\S+\]\s+(Ban|Unban)'],
        'parsing_rules': [{'type': 'action', 'regex': r'^\S+\s+\S+\s+fail2ban\.actions\s+\[\d+\]:\s+NOTICE\s+\[(?P<jail>\S+)\]\s+(?P<action>Ban|Unban)\s+(?P<ip>\S+)'}],
        'keywords': {'ACTION': {'Ban', 'Unban'}, 'COMPONENT': {'jail', 'actions'}},
        'thematic_grouping': {
            'banned_ips': lambda log: log.get('action') == 'Ban',
            'unbanned_ips': lambda log: log.get('action') == 'Unban',
        },
        'session_field': 'ip', 'timestamp_format': None, # Timestamp is part of a non-standard date string
        'timeline_formatter': lambda log: f"Fail2Ban [{log.get('jail')}] {log.get('action')} {log.get('ip')}."
    },
    'cisco_asa_firewall': {
        'name': 'Cisco ASA Firewall Log',
        'description': 'Logs from a Cisco ASA series firewall, typically via syslog.',
        'detection_patterns': [r'%ASA-\d-\d+:', r'Built connection', r'Teardown TCP connection'],
        'parsing_rules': [
            {'type': 'connection', 'regex': r'%ASA-\d-(?P<event_code>\d+): (?P<action>Built|Teardown) (?P<protocol>\S+) connection \d+ for (?P<direction>inbound|outbound) .*? to (?P<dest_ip>\S+)/\d+.* from (?P<src_ip>\S+)/\d+'},
            {'type': 'access', 'regex': r'%ASA-\d-(?P<event_code>\d+): (?P<action>Deny|Permit) (?P<protocol>\S+) src .*?:(?P<src_ip>\S+)/\d+ dst .*?:(?P<dest_ip>\S+)/\d+'},
        ],
        'keywords': {'CONNECTION_MGMT': {'Built', 'Teardown'}, 'ACCESS_CONTROL': {'Deny', 'Permit'}},
        'thematic_grouping': {'denied_traffic': lambda log: log.get('action') == 'Deny'},
        'session_field': 'src_ip', 'timestamp_format': None,
        'timeline_formatter': lambda log: f"{log.get('action')} {log.get('protocol')} from {log.get('src_ip')} to {log.get('dest_ip')}."
    },

    # --- Database Logs ---
    'postgresql_log': {
        'name': 'PostgreSQL Log',
        'description': 'Logs from the PostgreSQL database server.',
        'detection_patterns': [r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \w+ \[\d+\] LOG:', r'duration: \d+\.\d+ ms'],
        'parsing_rules': [{'type': 'query', 'regex': r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \w+) \[\d+\] (?P<level>LOG|ERROR|FATAL): \s+(?:duration: (?P<duration>\d+\.\d+) ms\s+)?statement: (?P<statement>.*)'}],
        'keywords': {'QUERY_TYPE': {'SELECT', 'INSERT', 'UPDATE', 'DELETE'}, 'SEVERITY': {'ERROR', 'FATAL'}},
        'thematic_grouping': {'slow_queries': lambda log: float(log.get('duration', 0)) > 1000},
        'session_field': None, 'timestamp_format': '%Y-%m-%d %H:%M:%S',
        'timeline_formatter': lambda log: f"{log.get('level')}: {log.get('statement')} (Duration: {log.get('duration')}ms)."
    },
    'mysql_slow_query_log': {
        'name': 'MySQL Slow Query Log',
        'description': 'Logs of SQL queries that took a long time to execute.',
        'detection_patterns': [r'^# Time: \d{6}\s+\d{1,2}:\d{2}:\d{2}', r'^# Query_time: '],
        'parsing_rules': [{'type': 'slow_query', 'regex': r'^# Query_time: (?P<query_time>\d+\.\d+)\s+Lock_time: (?P<lock_time>\d+\.\d+)\s+Rows_sent: (?P<rows_sent>\d+)\s+Rows_examined: (?P<rows_examined>\d+)\nSET timestamp=\d+;\n(?P<statement>.*);'}],
        'keywords': {'PERFORMANCE': {'Query_time', 'Lock_time'}},
        'thematic_grouping': {'very_slow_queries': lambda log: float(log.get('query_time', 0)) > 10},
        'session_field': None, 'timestamp_format': None,
        'timeline_formatter': lambda log: f"Slow query took {log.get('query_time')}s: {log.get('statement')}."
    },

    # --- Cloud & DevOps Logs ---
    'aws_cloudtrail_log': {
        'name': 'AWS CloudTrail Log (JSON)',
        'description': 'API activity and events for an AWS account.',
        'detection_patterns': [r'"eventSource": "\S+\.amazonaws\.com"', r'"awsRegion":'],
        'parsing_rules': [{'type': 'aws_event', 'is_json': True}],
        'keywords': {'IDENTITY': {'userIdentity', 'sourceIPAddress'}, 'EVENT': {'eventName', 'eventSource'}, 'ERROR': {'errorCode'}},
        'thematic_grouping': {'console_logins': lambda log: log.get('eventName') == 'ConsoleLogin'},
        'session_field': 'sourceIPAddress', 'timestamp_format': 'iso',
        'timeline_formatter': lambda log: f"AWS event '{log.get('eventName')}' by '{log.get('userIdentity', {}).get('arn')}' from {log.get('sourceIPAddress')}."
    },
    'docker_log': {
        'name': 'Docker Container Log',
        'description': 'Standard output from a running Docker container.',
        'detection_patterns': [r'^\S{12}\s', r'^[a-zA-Z0-9\-_/]+\s'], # Looks for container ID/name at start
        'parsing_rules': [{'type': 'container_out', 'regex': r'^(?P<container_id>\S{12})\s(?P<message>.*)'}],
        'keywords': {}, # Highly application-dependent
        'thematic_grouping': {},
        'session_field': 'container_id', 'timestamp_format': None,
        'timeline_formatter': lambda log: f"[{log.get('container_id')}] {log.get('message')}."
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
        'keywords': {'METADATA': {'commit', 'Author', 'Date'}, 'ACTIONS': {'fix', 'feat', 'refactor', 'docs', 'style'}},
        'thematic_grouping': {'feature_commits': lambda log: 'feat' in log.get('message', '')},
        'session_field': 'author', 'timestamp_format': None,
        'timeline_formatter': lambda log: f"Commit {log.get('commit_hash', '')[:7]} by {log.get('author', 'N/A')}: {log.get('message', 'No message')}."
    },

    # --- Generic & Developer Logs ---
    'python_traceback': {
        'name': 'Python Application Traceback',
        'description': 'Standard error output from Python applications.',
        'detection_patterns': [r'Traceback \(most recent call last\):', r'File ".*?", line \d+, in'],
        'parsing_rules': [
            {'type': 'error_header', 'regex': r'^(?P<traceback>Traceback \(most recent call last\):)'},
            {'type': 'file_path', 'regex': r'^\s+File "(?P<file_path>.*?)", line (?P<line_number>\d+), in (?P<function>.*)'},
            {'type': 'error_message', 'regex': r'^(?P<error_type>\w+Error): (?P<error_message>.*)'},
        ],
        'keywords': {'ERROR_CONTEXT': {'Traceback', 'File', 'line'}, 'ERROR_TYPE': {'ValueError', 'TypeError', 'KeyError'}},
        'thematic_grouping': {}, 'session_field': None, 'timestamp_format': None,
        'timeline_formatter': lambda log: f"Error '{log.get('error_type')}' in '{log.get('file_path')}' at line {log.get('line_number')}." if log.get('error_type') else 'Traceback context line.'
    },
    'json_log': {
        'name': 'JSON Log Format',
        'description': 'Logs where each line is a self-contained JSON object.',
        'detection_patterns': [r'^{.*"level":.*}$', r'^{.*"timestamp":.*}$'],
        'parsing_rules': [{'type': 'json_entry', 'is_json': True}],
        'keywords': {'SEVERITY': {'level', 'severity'}, 'METADATA': {'timestamp', 'hostname'}, 'ERROR': {'error', 'exception'}},
        'thematic_grouping': {'errors': lambda log: log.get('level', '').lower() in ['error', 'critical', 'fatal']},
        'session_field': 'hostname', 'timestamp_format': 'iso',
        'timeline_formatter': lambda log: log.get('message', next((v for k, v in log.items() if k not in ['timestamp', 'level']), 'JSON entry'))
    },
    'generic': { # Fallback profile
        'name': 'Generic Text File',
        'description': 'A generic profile for unrecognized text files.',
        'detection_patterns': [], 'parsing_rules': [{'type': 'generic', 'regex': r'^(?P<line_content>.*)'}],
        'keywords': {}, 'thematic_grouping': {}, 'session_field': None, 'timestamp_format': None,
        'timeline_formatter': lambda log: log.get('line_content', 'Generic Line')
    }
}

# #############################################################################
# SECTION 2: THE panomreles CORE CLASS
# Orchestrates the entire analysis process.
# #############################################################################

class panomreles:
    """The main orchestrator for the log analysis multitool."""

    def __init__(self, filepath, config=None):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"The file '{filepath}' was not found.")
        
        self.filepath = filepath
        self.basename = os.path.splitext(os.path.basename(filepath))[0]
        self.config = config or {}
        
        self.output_dir = self.config.get('custom_output_dir', f"{self.basename}_panomreles_results")
        
        self.lines = self._load_file()
        self.total_lines = len(self.lines)
        self.profile_key, self.profile = self._detect_profile()
        self.parsed_logs = self._parse_logs()

    def _load_file(self):
        encodings_to_try = ['utf-8-sig', 'latin-1', 'utf-16']
        for enc in encodings_to_try:
            try:
                with open(self.filepath, 'r', encoding=enc) as f:
                    return [line.strip() for line in f if line.strip()]
            except UnicodeDecodeError:
                continue
        raise ValueError("Could not decode the file with common encodings.")

    def _setup_output_directory(self):
        """Creates a clean directory structure for the analysis results."""
        if os.path.exists(self.output_dir):
            # If a custom dir is provided, we don't want to delete it.
            # We'll just ensure subdirectories exist.
            pass
        else:
            os.makedirs(self.output_dir, exist_ok=True)
            
        os.makedirs(os.path.join(self.output_dir, 'reports'), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, 'raw_data_exports'), exist_ok=True)

    def _detect_profile(self):
        scores = Counter()
        for key, profile in LOG_PROFILES.items():
            if not profile.get('detection_patterns'): continue
            for pattern in profile['detection_patterns']:
                try:
                    # Score based on how many of the first 200 lines match
                    scores[key] += sum(1 for line in self.lines[:200] if re.search(pattern, line))
                except re.error:
                    print(f"Warning: Invalid regex in profile '{key}': {pattern}")
        
        if not scores or scores.most_common(1)[0][1] == 0:
            return 'generic', LOG_PROFILES['generic']
        best_profile_key = scores.most_common(1)[0][0]
        return best_profile_key, LOG_PROFILES[best_profile_key]

    def _parse_logs(self):
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
                    except json.JSONDecodeError: continue
                
                match = re.search(rule['regex'], line)
                if match:
                    log_entry.update(match.groupdict())
                    log_entry['log_type'] = rule.get('type', 'unknown')
                    matched = True
                    break
            
            if not matched: log_entry['log_type'] = 'unmatched'
            parsed.append(log_entry)
        return parsed

    def run_full_analysis(self):
        print(BANNER)
        print(f"Analyzing '{os.path.basename(self.filepath)}' ({self.total_lines:,} lines)...")
        self._setup_output_directory()
        print(f"-> Output will be saved to: '{self.output_dir}/'")
        print(f"-> Detected Profile: '{self.profile['name']}'")

        analyzer = LogAnalyzer(self.parsed_logs, self.profile)
        analysis_results = analyzer.run_all_analyses()
        
        reporter = ReportGenerator(self.output_dir, self.basename, analysis_results, self.parsed_logs, self.config)
        reporter.generate_all_reports()
        
        print("\nAnalysis complete. Check the output directory for your intelligence package.")
        return analysis_results

# #############################################################################
# SECTION 3: THE LOG ANALYZER CLASS
# #############################################################################

class LogAnalyzer:
    """Performs various analytical tasks on parsed log data."""

    def __init__(self, parsed_logs, profile):
        self.logs = parsed_logs
        self.profile = profile
        self.results = {'profile_name': profile['name']}
        self._parse_timestamps()

    def _parse_timestamps(self):
        """A helper to parse timestamps for all logs at once."""
        ts_format = self.profile.get('timestamp_format')
        if not ts_format: return

        for log in self.logs:
            ts_str = log.get('timestamp')
            if self.profile['name'] == 'Microsoft IIS Log (W3C)' and 'date' in log and 'time' in log:
                ts_str = f"{log['date']} {log['time']}"
            
            if not ts_str: continue
            
            try:
                ts_str_clean = ts_str.split(',')[0].strip()
                if ts_format == 'iso':
                    log['datetime'] = datetime.fromisoformat(ts_str_clean.replace('Z', '+00:00'))
                elif ts_format == '%b %d %H:%M:%S':
                     ts = datetime.strptime(ts_str_clean, ts_format)
                     current_time = datetime.now()
                     log['datetime'] = ts.replace(year=current_time.year if ts.month <= current_time.month else current_time.year - 1)
                else:
                    log['datetime'] = datetime.strptime(ts_str_clean, ts_format)
            except (ValueError, TypeError):
                continue

    def run_all_analyses(self):
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
        print("-> Analyzing sessions...")
        self.results['sessions'] = self._analyze_sessions()
        print("-> Checking Threat Intelligence (mock)...")
        self.results['threat_intel'] = self._check_threat_intelligence()
        print("-> Performing cross-listing analysis...")
        self.results['cross_listing'] = self._analyze_cross_listing()
        print("-> Generating inferences...")
        self.results['inferences'] = self._generate_inferences()
        return self.results

    def _calculate_stats(self):
        stats = {'total_events': len(self.logs)}
        timestamps = [log['datetime'] for log in self.logs if 'datetime' in log]
        
        if timestamps:
            duration = (max(timestamps) - min(timestamps)).total_seconds()
            stats['time_span_minutes'] = duration / 60
            if stats['time_span_minutes'] > 0:
                stats['events_per_minute'] = stats['total_events'] / stats['time_span_minutes']
        return stats
    
    def _analyze_errors(self):
        error_keywords = self.profile.get('keywords', {}).get('ERROR', set()) | \
                         self.profile.get('keywords', {}).get('RESPONSE_ERROR', set())
        
        error_logs = [log for log in self.logs if any(kw.lower() in log['original_line'].lower() for kw in error_keywords)]
        return {'count': len(error_logs), 'top_errors': Counter(log['original_line'] for log in error_logs).most_common(5)}
        
    def _analyze_context(self):
        topic_counts = Counter()
        keyword_map = self.profile.get('keywords', {})
        if not keyword_map: return {}

        text_blob = " ".join(log['original_line'] for log in self.logs).lower()
        for category, keywords in keyword_map.items():
            topic_counts[category] = sum(text_blob.count(kw.lower()) for kw in keywords)
        
        total_keywords = sum(topic_counts.values())
        if not total_keywords: return {}
            
        return {topic: (count / total_keywords) * 100 for topic, count in topic_counts.items()}

    def _find_top_events(self, n=10):
        def templatize(log):
            msg = log.get('message', log['original_line'])
            msg = re.sub(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 'IP_ADDR', msg)
            msg = re.sub(r'0x[0-9a-fA-F]+', 'HEX_ADDR', msg)
            msg = re.sub(r'pid=\d+', 'pid=PID', msg)
            msg = re.sub(r'\[\d+\]', '[PID]', msg)
            msg = re.sub(r'line \d+', 'line LINE_NUM', msg)
            msg = re.sub(r'\d{5,}', 'LONG_NUM', msg)
            return msg
        return Counter(templatize(log) for log in self.logs).most_common(n)

    def _build_relationship_graph(self, window_size=5):
        graph = defaultdict(Counter)
        keywords_flat = [kw.lower() for kws in self.profile.get('keywords', {}).values() for kw in kws]
        if not keywords_flat: return []
        
        for i in range(len(self.logs) - window_size):
            window_text = " ".join(self.logs[j]['original_line'].lower() for j in range(i, i + window_size))
            present_keywords = {kw for kw in keywords_flat if kw in window_text}
            
            present_list = list(present_keywords)
            for j in range(len(present_list)):
                for k in range(j + 1, len(present_list)):
                    kw1, kw2 = sorted((present_list[j], present_list[k]))
                    graph[kw1][kw2] += 1
                        
        top_relations = []
        for kw1, others in graph.items():
            for kw2, score in others.items():
                top_relations.append(((kw1, kw2), score))
        
        return sorted(top_relations, key=lambda x: x[1], reverse=True)[:10]

    def _detect_anomalies(self):
        anomalies = []
        timestamps = [log['datetime'] for log in self.logs if 'datetime' in log]
        if len(timestamps) < 20: return []

        events_per_minute = Counter(t.strftime('%Y-%m-%d %H:%M') for t in timestamps)
        counts = list(events_per_minute.values())
        if not counts: return []
        
        mean = sum(counts) / len(counts)
        std_dev = math.sqrt(sum((x - mean) ** 2 for x in counts) / len(counts)) if len(counts) > 1 else 0
        threshold = mean + (3 * std_dev)
        
        for minute, count in events_per_minute.items():
            if count > threshold and count > 10:
                anomaly_desc = f"High activity spike: {count} events at {minute} (mean is {mean:.1f}, threshold is {threshold:.1f})."
                anomalies.append(anomaly_desc)
        return anomalies

    def _analyze_sessions(self, timeout_minutes=30):
        session_field = self.profile.get('session_field')
        if not session_field: return {}

        sessions = defaultdict(list)
        for log in self.logs:
            if session_field in log and 'datetime' in log:
                sessions[log[session_field]].append(log['datetime'])

        if not sessions: return {}
            
        session_stats = []
        for identifier, timestamps in sessions.items():
            timestamps.sort()
            if not timestamps: continue
            
            duration = (timestamps[-1] - timestamps[0]).total_seconds() / 60
            session_stats.append({'id': identifier, 'event_count': len(timestamps), 'duration_min': duration})
        
        avg_duration = sum(s['duration_min'] for s in session_stats) / len(session_stats) if session_stats else 0
        
        return {
            'session_count': len(sessions),
            'avg_duration_min': avg_duration,
            'top_sessions_by_events': sorted(session_stats, key=lambda s: s['event_count'], reverse=True)[:5]
        }

    def _check_threat_intelligence(self):
        watchlist = {
            "198.51.100.55": "Known Botnet Controller",
            "203.0.113.12": "Malware Distribution Host",
            "185.191.171.13": "Scanning/Probing Host",
            "104.28.2.98": "Phishing Site Host"
        }

        ips = set()
        for log in self.logs:
            ip_str = log.get('ip', '') + log.get('src_ip', '') + log.get('dest_ip', '') + log['original_line']
            found_ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ip_str)
            for ip in found_ips:
                if not (ip.startswith(('10.', '192.168.', '172.16.', '127.0.')) or ip == '0.0.0.0'):
                    ips.add(ip)
        
        hits = {ip: reason for ip, reason in watchlist.items() if ip in ips}
        
        return {'ips_scanned': len(ips), 'watchlist_hits': hits}
    
    def _analyze_cross_listing(self):
        """Analyzes which log lines appear in the most thematic groups."""
        grouping_rules = self.profile.get('thematic_grouping', {})
        if not grouping_rules: return {}
        
        line_scores = Counter()
        for log in self.logs:
            for theme, rule in grouping_rules.items():
                if rule(log):
                    line_scores[log['line_number']] += 1
        
        top_cross_listed = line_scores.most_common(5)
        return {
            'top_events': [
                {'line_number': ln, 'categories': score, 'content': self.logs[ln-1]['original_line']}
                for ln, score in top_cross_listed if score > 1
            ]
        }
        
    def _generate_inferences(self):
        """Generates high-level inferences based on combined analysis results."""
        inferences = []
        stats = self.results.get('stats', {})
        errors = self.results.get('errors', {})
        context = self.results.get('context', {})
        threats = self.results.get('threat_intel', {})
        
        error_rate = errors.get('count', 0) / (stats.get('total_events', 1) or 1)
        if threats.get('watchlist_hits'):
            inferences.append("CRITICAL: The log contains interactions with IPs on a threat intelligence watchlist, indicating a potential security breach or targeted attack.")
        elif error_rate > 0.1:
            inferences.append(f"POOR HEALTH: A high error rate ({error_rate:.1%}) suggests the system is unstable or misconfigured.")
        elif error_rate > 0.01:
            inferences.append(f"NEEDS ATTENTION: A moderate error rate ({error_rate:.1%}) suggests minor but persistent issues that should be investigated.")
        else:
            inferences.append("GOOD HEALTH: The system appears to be operating with a low error rate, suggesting general stability.")
            
        if context.get('AGENT_METADATA', 0) > 50:
            inferences.append("The log is dominated by agent metadata, suggesting a period of idling or internal processing rather than active tool use.")
        elif context.get('GUI_INTERACTION', 0) > 50:
            inferences.append("The log shows a high degree of GUI interaction, indicating the agent was actively performing a task on a target system.")
        
        top_events = self.results.get('top_events', [])
        if top_events and top_events[0][1] > stats.get('total_events', 1) * 0.25:
             inferences.append(f"The event '{top_events[0][0][:50]}...' is extremely repetitive, suggesting a component might be stuck in a loop or flooding the logs.")
             
        return inferences

# #############################################################################
# SECTION 4: THE REPORT GENERATOR
# #############################################################################

class ReportGenerator:
    """Generates the full, structured output package."""
    
    def __init__(self, output_dir, base_filename, analysis_results, parsed_logs, config):
        self.output_dir = output_dir
        self.base_filename = base_filename
        self.results = analysis_results
        self.logs = parsed_logs
        self.profile = LOG_PROFILES.get(self.results.get('profile_key', 'generic'), LOG_PROFILES['generic'])
        self.config = config

    def generate_all_reports(self):
        """Master function to generate all output files."""
        if self.config.get('export_raw_data', True):
            print("-> Exporting thematic raw data...")
            self._export_thematic_data()
        
        if self.config.get('generate_briefing', True):
            print("-> Generating intelligence briefing...")
            self._generate_briefing()

        if self.config.get('generate_text_report', True):
            print("-> Generating text report...")
            self._generate_text_report()
        
        if self.config.get('generate_html_report', True):
            print("-> Generating HTML report...")
            self._generate_html_report()

    def _export_thematic_data(self):
        grouping_rules = self.profile.get('thematic_grouping', {})
        if not grouping_rules: return

        data_dir = os.path.join(self.output_dir, 'raw_data_exports')
        
        for theme, rule in grouping_rules.items():
            themed_logs = [log['original_line'] for log in self.logs if rule(log)]
            if themed_logs:
                theme_dir = os.path.join(data_dir, theme)
                os.makedirs(theme_dir, exist_ok=True)
                with open(os.path.join(theme_dir, f"{theme}.log"), 'w', encoding='utf-8') as f:
                    f.write('\n'.join(themed_logs))

    def _generate_briefing(self):
        path = os.path.join(self.output_dir, 'intelligence_briefing.md')
        inferences = self.results.get('inferences', [])
        stats = self.results.get('stats', {})
        errors = self.results.get('errors', {})
        threats = self.results.get('threat_intel', {})
        anomalies = self.results.get('anomalies', [])
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"# Intelligence Briefing: {self.base_filename}\n\n")
            f.write(f"**Analysis Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Log Type:** {self.results['profile_name']}\n\n")
            
            f.write("## Executive Summary\n")
            f.write(f"Analysis of **{stats.get('total_events', 0):,}** events revealed **{errors.get('count', 0)}** errors")
            if threats.get('watchlist_hits'): f.write(f", and **{len(threats['watchlist_hits'])}** threat intelligence hits. ")
            else: f.write(". ")
            if anomalies: f.write(f"Additionally, **{len(anomalies)}** significant anomalies were detected.\n\n")
            else: f.write("No significant anomalies were detected.\n\n")

            if inferences:
                f.write("## Key Inferences\n")
                for inference in inferences: f.write(f"- **Conclusion:** {inference}\n")
                f.write("\n")

            if threats.get('watchlist_hits'):
                f.write("## ❗ Threat Intelligence Hits\n")
                f.write("| IP Address | Reason |\n|------------|--------|\n")
                for ip, reason in threats['watchlist_hits'].items(): f.write(f"| `{ip}` | {reason} |\n")
                f.write("\n")

            if anomalies:
                f.write("## 📈 Anomalies Detected\n")
                for anom in anomalies: f.write(f"- {anom}\n")
                f.write("\n")

            if errors.get('top_errors'):
                f.write("## ⚙️ Top Error Messages\n")
                for msg, count in errors['top_errors']: f.write(f"- **(x{count})** `{msg[:120]}`\n")
                f.write("\n")

            f.write("## Recommendations\n")
            if threats.get('watchlist_hits'): f.write("- **Immediate Action:** Investigate and block all IPs flagged by the threat intelligence watchlist.\n")
            error_rate = errors.get('count', 0) / (stats.get('total_events', 1) or 1)
            if error_rate > 0.05: f.write("- **High Priority:** The high volume of errors suggests a potential stability issue.\n")
            if anomalies: f.write("- **Investigation:** The detected activity spikes are unusual. Correlate timestamps with known system events.\n")
            f.write("- **Further Analysis:** Review the full HTML report and thematic raw data exports for a deeper dive.\n")
    
    def _generate_text_report(self):
        path = os.path.join(self.output_dir, 'reports', self.base_filename + "_analysis.txt")
        with open(path, 'w', encoding='utf-8') as f:
             f.write(BANNER + "\n" + "="*60 + "\n  Titan Analysis Report\n" + "="*60 + "\n\n")
             f.write(f"Profile: {self.results['profile_name']}\n")
             
             stats = self.results.get('stats', {})
             f.write("\n---[ Statistics ]---\n")
             for key, val in stats.items():
                 formatted_val = f"{val:,.2f}" if isinstance(val, float) else f"{val:,}"
                 f.write(f"- {key.replace('_', ' ').title()}: {formatted_val}\n")

             context = self.results.get('context', {})
             f.write("\n---[ Context Analysis ]---\n")
             if context:
                 for topic, pct in sorted(context.items(), key=lambda x: x[1], reverse=True):
                     f.write(f"- {topic.replace('_', ' ').title()}: {pct:.1f}%\n")
             else: f.write("N/A\n")

             errors = self.results.get('errors', {})
             f.write(f"\n---[ Error Analysis ]---\n")
             f.write(f"Total Errors Found: {errors.get('count', 0)}\n")
             if errors.get('top_errors'):
                 for msg, count in errors['top_errors']: f.write(f"  (x{count}) {msg[:100]}...\n")

             f.write("\n---[ Top 10 Most Common Events ]---\n")
             for msg, count in self.results.get('top_events', []): f.write(f"  (x{count}) {msg[:100]}...\n")
             
             f.write("\n---[ Top 10 Keyword Relationships ]---\n")
             for (kw1, kw2), score in self.results.get('relationships', []): f.write(f"- '{kw1}' <-> '{kw2}' (Score: {score})\n")

             f.write("\n---[ Detected Anomalies ]---\n")
             anomalies = self.results.get('anomalies', [])
             if anomalies:
                 for anomaly in anomalies: f.write(f"- {anomaly}\n")
             else: f.write("No significant anomalies detected.\n")

             sessions = self.results.get('sessions', {})
             if sessions:
                 f.write("\n---[ Session Analysis ]---\n")
                 f.write(f"Total Sessions: {sessions.get('session_count', 0)}\n")
                 f.write(f"Avg Duration (min): {sessions.get('avg_duration_min', 0):.2f}\n")
                 for s in sessions.get('top_sessions_by_events', []): f.write(f"  - ID '{s['id']}': {s['event_count']} events, {s['duration_min']:.2f} min\n")

             threats = self.results.get('threat_intel', {})
             f.write("\n---[ Threat Intelligence Report (Mock) ]---\n")
             f.write(f"Public IPs Scanned: {threats.get('ips_scanned', 0)}\n")
             if threats.get('watchlist_hits'):
                 f.write("!! WATCHLIST HITS !!\n")
                 for ip, reason in threats['watchlist_hits'].items(): f.write(f"  - {ip}: {reason}\n")
             else: f.write("No watchlist hits found.\n")
             
             cross_listing = self.results.get('cross_listing', {})
             if cross_listing.get('top_events'):
                 f.write("\n---[ Cross-Listing Analysis (Most Versatile Events) ]---\n")
                 for event in cross_listing['top_events']:
                     f.write(f"- Line {event['line_number']} in {event['categories']} categories: {event['content'][:80]}...\n")


    def _generate_html_report(self):
        path = os.path.join(self.output_dir, 'reports', self.base_filename + "_analysis.html")
        
        context_data = self.results.get('context', {})
        context_labels = json.dumps(list(context_data.keys()))
        context_values = json.dumps(list(context_data.values()))
        
        top_events = self.results.get('top_events', [])
        top_events_labels = json.dumps([f"{evt[:30]}..." for evt, count in top_events])
        top_events_values = json.dumps([count for evt, count in top_events])

        html_template = f"""
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>panomreles Report: {self.base_filename}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script><style>
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;margin:0;background-color:#f8f9fa;color:#343a40}}
.container{{max-width:1400px;margin:auto;padding:20px}}.header{{background-color:#343a40;color:white;padding:40px;text-align:center}}
h1{{margin:0;font-size:2.5em}}h2{{margin-top:0;border-bottom:2px solid #e9ecef;padding-bottom:10px;color:#495057}}
p.subtitle{{margin-top:5px;font-size:1.2em;color:#adb5bd}}
.grid-container{{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:20px;margin-top:20px}}
.card{{background:white;border-radius:8px;box-shadow:0 4px 6px rgba(0,0,0,0.1);padding:20px}}.card.full-width{{grid-column:1/-1}}
.stat-grid{{display:grid;grid-template-columns:1fr 1fr;gap:15px;text-align:center}}
.stat-item h3{{margin:0 0 5px 0;font-size:2em;color:#007bff}}.stat-item p{{margin:0;color:#6c757d}}
.threat{{color:#dc3545;font-weight:bold}}.table-container{{max-height:300px;overflow-y:auto}}
table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:8px;border-bottom:1px solid #dee2e6}}
th{{background-color:#f8f9fa}}
ul{{padding-left:20px}} li{{margin-bottom:10px}}
</style></head><body><div class="header"><h1>panomreles Titan Report</h1><p class="subtitle">{self.base_filename}</p></div>
<div class="container">
<div class="card full-width"><h2>Executive Summary</h2><p><strong>Profile:</strong> {self.results['profile_name']}</p>
<h3>Key Inferences</h3><ul>{"".join(f"<li>{inf}</li>" for inf in self.results.get('inferences', []))}</ul></div>
<div class="grid-container">
<div class="card"><div class="stat-grid">
<div class="stat-item"><h3>{self.results.get('stats', {}).get('total_events', 0):,}</h3><p>Total Events</p></div>
<div class="stat-item"><h3>{self.results.get('stats', {}).get('events_per_minute', 0):.1f}</h3><p>Events/Min</p></div>
<div class="stat-item"><h3 class="{ 'threat' if self.results.get('errors', {}).get('count',0) > 0 else '' }">{self.results.get('errors', {}).get('count',0):,}</h3><p>Errors</p></div>
<div class="stat-item"><h3 class="{ 'threat' if self.results.get('threat_intel', {}).get('watchlist_hits') else '' }">{len(self.results.get('threat_intel', {}).get('watchlist_hits', []))}</h3><p>Threats</p></div>
</div></div>
<div class="card"><h2>Context Analysis</h2><canvas id="contextChart"></canvas></div>
</div>
<div class="card full-width"><h2>Top Events & Anomalies</h2><div class="grid-container">
<div class="card"><h3>Top 10 Most Common Events</h3><div class="table-container"><table><thead><tr><th>Count</th><th>Event Template</th></tr></thead><tbody>
{"".join(f"<tr><td>{count}</td><td>{evt}</td></tr>" for evt, count in self.results.get('top_events', []))}
</tbody></table></div></div>
<div class="card"><h3>Anomalies & Threats</h3>
<h4>Anomalies</h4><ul>{"".join(f"<li>{anom}</li>" for anom in self.results.get('anomalies', [])) or "<li>None Detected</li>"}</ul>
<h4>Threat Intelligence Hits</h4>
{"<table><thead><tr><th>IP</th><th>Reason</th></tr></thead><tbody>" + "".join(f"<tr><td>{ip}</td><td class='threat'>{reason}</td></tr>" for ip, reason in self.results.get('threat_intel', {}).get('watchlist_hits', {}).items()) + "</tbody></table>" if self.results.get('threat_intel',{}).get('watchlist_hits') else "<p>None Detected</p>"}
</div></div></div>
</div></body><script>
new Chart(document.getElementById('contextChart'), {{ type: 'pie', data: {{ labels: {context_labels}, datasets: [{{ label: 'Context Distribution', data: {context_values}, backgroundColor: ['#007bff','#28a745','#dc3545','#ffc107','#17a2b8','#6c757d'] }}] }}, options: {{ responsive: true, plugins: {{ legend: {{ position: 'top' }} }} }} }});
</script></html>
"""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_template)

# #############################################################################
# SECTION 5: ONBOARDING & COMMAND-LINE INTERFACE
# #############################################################################

def display_onboarding():
    print(BANNER)
    print("\nWelcome to panomreles Titan! This is your onboarding guide.\n")
    print("======================================================================")
    print("WHAT IT IS: A log analysis platform that takes any log file, automatically")
    print("            identifies it, and generates a full intelligence package.")
    print("\nHOW TO USE:")
    print("1. Run the script: python panomreles.py /path/to/your/logfile.log")
    print("2. A new folder named 'logfile_panomreles_results' will be created.")
    print("3. Explore the output package inside that folder.\n")
    print("WHAT YOU GET:")
    print("  - /reports/              -> Detailed HTML dashboard and full text analysis.")
    print("  - /raw_data_exports/     -> The original log lines, split into thematic subfolders.")
    print("  - intelligence_briefing.md -> A high-level summary of the most critical findings.\n")
    print("HOW TO EXTEND (The fun part!):")
    print("  - Open this script (`panomreles.py`) in a text editor.")
    print("  - Find the 'LOG_PROFILES' dictionary near the top.")
    print("  - Copy an existing profile (like 'apache_access_log') and modify it for your new log type.")
    print("  - You just need to define a 'detection_pattern' and a 'parsing_rule'.")
    print("  - panomreles will automatically handle the rest!")
    print("======================================================================")

# --- New Plugin Entry Point ---
def analyze(filepath, config=None):
    """
    This is the primary entry point for using panomreles as a plugin.
    
    Args:
        filepath (str): The absolute path to the log file to analyze.
        config (dict, optional): A dictionary to override default behavior.
            'custom_output_dir': (str) Specify a different output directory.
            'generate_html_report': (bool) Defaults to True.
            'generate_text_report': (bool) Defaults to True.
            'generate_briefing': (bool) Defaults to True.
            'export_raw_data': (bool) Defaults to True.
    
    Returns:
        dict: A dictionary containing the full analysis results.
    """
    if config is None:
        config = {}
    
    titan_tool = panomreles(filepath, config=config)
    analysis_results = titan_tool.run_full_analysis()
    return analysis_results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=BANNER, 
        epilog="Example: python panomreles.py my_app.log",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("logfile", nargs='?', default=None, help="Path to the log file to be analyzed.")
    parser.add_argument("-onboarding", "--onboarding", action="store_true", help="Display the user onboarding guide and exit.")
    args = parser.parse_args()
    
    if args.onboarding or not args.logfile:
        display_onboarding()
    else:
        try:
            analyze(args.logfile)
        except Exception as e:
            print(f"\n--- [ CRITICAL ERROR ] ---")
            print(f"An error occurred: {e}")
            print("Please check the file path and ensure it is a readable text file.")

