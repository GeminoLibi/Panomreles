#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  Panomreles - The Panomreles Log Profile Library
#  Version: 1.0.0
#  Author: Gemini & GeminoLibi
#  Purpose: A standalone, comprehensive, and extensible library of log file profiles.
#           This is the "brain" that powers the Panomreles analysis engine.
#  Find the platform you're interested in and copy/paste it into your script. If you find better patterns or better keywords, please contribute, along with new log types! 

LOG_PROFILES = {
    # --- Agent & Automation Logs ---
    'anthropic_tool_log': {
        'name': 'Anthropic Agent Low-Level Tool Log',
        'description': 'Logs from a Claude agent interacting with a tool, showing GUI actions and agent-tool communication.',
        'example': '[2025-10-05 13:16:38] [INFO] logger - action: mouse_move, text: None, coordinate: (152, 152)',
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
    },

    # --- Web Server Logs ---
    'apache_access_log': {
        'name': 'Apache Web Access Log',
        'description': 'Standard log format for the Apache web server, detailing incoming HTTP requests.',
        'example': '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I)"',
        'detection_patterns': [r'^\S+ \S+ \S+ \[.*?\] "GET|POST|HEAD', r'HTTP/1\.[01]" \d{3}'],
        'parsing_rules': [{'type': 'access', 'regex': r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<timestamp>.*?)\].*?"(?P<method>GET|POST|HEAD)\s(?P<url>.*?)\s.*?"\s(?P<status>\d{3})\s(?P<size>\S+)\s"(?P<referrer>.*?)"\s"(?P<user_agent>.*?)"'}],
        'keywords': {'REQUEST': {'GET', 'POST', 'HEAD'}, 'CLIENT_INFO': {'ip', 'user'}, 'RESPONSE_SUCCESS': {'200', '301'}, 'RESPONSE_ERROR': {'404', '500', '403'}, 'ATTACK_VECTOR': {'select', 'union', 'script', 'alert', '../'}},
        'thematic_grouping': {
            'errors_4xx': lambda log: log.get('status', '').startswith('4'),
            'errors_5xx': lambda log: log.get('status', '').startswith('5'),
            'successful_requests': lambda log: log.get('status', '').startswith('2'),
            'redirects': lambda log: log.get('status', '').startswith('3'),
            'bot_traffic': lambda log: any(bot in log.get('user_agent', '').lower() for bot in ['bot', 'spider', 'crawler', 'slurp']),
            'potential_sqli': lambda log: 'union' in log.get('url', '').lower() and 'select' in log.get('url', '').lower(),
            'potential_xss': lambda log: '<script' in log.get('url', '').lower() or 'alert(' in log.get('url', '').lower(),
            'potential_lfi': lambda log: '../' in log.get('url', ''),
            'traffic_by_method_get': lambda log: log.get('method') == 'GET',
            'traffic_by_method_post': lambda log: log.get('method') == 'POST',
        },
        'session_field': 'ip', 'timestamp_format': '%d/%b/%Y:%H:%M:%S %z',
    },
    'nginx_access_log': {
        'name': 'Nginx Web Access Log',
        'description': 'Standard log format for the Nginx web server.',
        'example': '192.168.1.1 - - [05/Oct/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        'detection_patterns': [r'^\S+ - \S+ \[.*?\] "GET|POST|HEAD', r'HTTP/2\.0" \d{3}'],
        'parsing_rules': [{'type': 'access', 'regex': r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<timestamp>.*?)\].*?"(?P<method>GET|POST|HEAD)\s(?P<url>.*?)\s.*?"\s(?P<status>\d{3})\s(?P<size>\S+)\s"(?P<referrer>.*?)"\s"(?P<user_agent>.*?)"'}],
        'keywords': {'REQUEST': {'GET', 'POST'}, 'CLIENT_INFO': {'ip', 'user_agent'}, 'RESPONSE_ERROR': {'404', '499', '502'}},
        'thematic_grouping': {
            'errors_4xx': lambda log: log.get('status', '').startswith('4'),
            'errors_5xx': lambda log: log.get('status', '').startswith('5'),
        },
        'session_field': 'ip', 'timestamp_format': '%d/%b/%Y:%H:%M:%S %z',
    },
    'iis_log': {
        'name': 'Microsoft IIS Log (W3C)',
        'description': 'Logs from Microsoft\'s Internet Information Services web server.',
        'example': '2025-10-05 12:00:00 10.0.0.1 GET /default.htm - 80 - 10.0.0.100 Mozilla/5.0 200',
        'detection_patterns': [r'^#Software: Microsoft Internet Information Services', r'^#Fields: date time s-ip cs-method'],
        'parsing_rules': [{'type': 'access', 'regex': r'^(?P<date>\S+)\s(?P<time>\S+)\s(?P<s_ip>\S+)\s(?P<cs_method>\S+)\s(?P<cs_uri_stem>\S+)\s(?P<cs_uri_query>\S+)\s(?P<s_port>\d+)\s(?P<cs_username>\S+)\s(?P<c_ip>\S+)\s(?P<cs_user_agent>\S+)\s(?P<sc_status>\d+)'}],
        'keywords': {'REQUEST': {'GET', 'POST'}, 'CLIENT_INFO': {'c_ip', 'cs_user_agent'}, 'RESPONSE_ERROR': {'404', '500'}},
        'thematic_grouping': {'errors': lambda log: log.get('sc_status', '').startswith(('4', '5'))},
        'session_field': 'c_ip', 'timestamp_format': '%Y-%m-%d %H:%M:%S', 
    },

    # --- System & Security Logs ---
    'linux_syslog': {
        'name': 'Linux Syslog (Standard)',
        'description': 'Generic system messages for Linux operating systems.',
        'example': 'Oct  5 12:05:01 my-server CRON[12345]: (root) CMD (command)',
        'detection_patterns': [r'^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ \S+\[\d+\]:', r'CRON\[\d+\]:'],
        'parsing_rules': [{'type': 'system', 'regex': r'^(?P<timestamp>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) (?P<process>\S+?)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)'}],
        'keywords': {'SYSTEM_DAEMON': {'cron', 'systemd', 'sshd'}, 'AUTHENTICATION': {'session opened', 'authentication failure'}, 'ERROR': {'error', 'failed'}},
        'thematic_grouping': {
            'auth_events': lambda log: 'session' in log.get('message', '').lower() or 'authentication' in log.get('message', '').lower(),
            'cron_jobs': lambda log: 'cron' in log.get('process', '').lower(),
            'kernel_messages': lambda log: 'kernel' in log.get('process', '').lower(),
            'sudo_events': lambda log: 'sudo' in log.get('process', '').lower(),
        },
        'session_field': 'process', 'timestamp_format': '%b %d %H:%M:%S',
    },
    'windows_event_log_csv': {
        'name': 'Windows Event Log (CSV)',
        'description': 'Exported logs from Windows Event Viewer in CSV format.',
        'example': '"Information","2025-10-05T12:00:00.123Z","Service Control Manager","7036","None","The Application Experience service entered the running state."',
        'detection_patterns': [r'"Level","Date and Time","Source","Event ID",', r'System,Microsoft-Windows-'],
        'parsing_rules': [{'type': 'event', 'regex': r'"(?P<level>[^"]+)","(?P<timestamp>[^"]+)","(?P<source>[^"]+)","(?P<event_id>[^"]+)","(?P<task_category>[^"]+)","(?P<message>.*)"'}],
        'keywords': {'SEVERITY_HIGH': {'Critical', 'Error'}, 'SECURITY': {'Audit Success', 'Audit Failure'}, 'SYSTEM': {'Kernel-Power'}},
        'thematic_grouping': {
            'critical_errors': lambda log: log.get('level') == 'Critical',
            'security_audits': lambda log: 'audit' in log.get('task_category', '').lower(),
            'user_logon_events': lambda log: log.get('event_id') == '4624', # Successful Logon
            'failed_logon_events': lambda log: log.get('event_id') == '4625', # Failed Logon
        },
        'session_field': 'Source', 'timestamp_format': 'iso', 
    },
    'sshd_log': {
        'name': 'OpenSSH Server Log',
        'description': 'Authentication and session logs from the OpenSSH daemon.',
        'example': 'Oct  5 12:00:00 auth-server sshd[12345]: Failed password for invalid user bob from 192.0.2.100 port 12345 ssh2',
        'detection_patterns': [r'sshd\[\d+\]: Accepted password for', r'sshd\[\d+\]: Failed password for'],
        'parsing_rules': [{'type': 'auth', 'regex': r'^(?P<timestamp>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: (?P<message>(?:Accepted|Failed|Invalid user) .* from (?P<ip>\S+))'}],
        'keywords': {'AUTH_SUCCESS': {'Accepted password', 'session opened'}, 'AUTH_FAILURE': {'Failed password', 'Invalid user'}},
        'thematic_grouping': {
            'successful_logins': lambda log: 'Accepted' in log.get('message', ''),
            'failed_logins': lambda log: 'Failed' in log.get('message', ''),
            'invalid_users': lambda log: 'Invalid user' in log.get('message', ''),
        },
        'session_field': 'ip', 'timestamp_format': '%b %d %H:%M:%S',
    },
    'fail2ban_log': {
        'name': 'Fail2Ban Log',
        'description': 'Logs from the Fail2Ban intrusion prevention software.',
        'example': '2025-10-05 12:00:00,123 fail2ban.actions[12345]: NOTICE [sshd] Ban 192.0.2.100',
        'detection_patterns': [r'fail2ban\.actions\s+\[\d+\]:', r'NOTICE\s+\[\S+\]\s+(Ban|Unban)'],
        'parsing_rules': [{'type': 'action', 'regex': r'^\S+\s+\S+\s+fail2ban\.actions\s+\[\d+\]:\s+NOTICE\s+\[(?P<jail>\S+)\]\s+(?P<action>Ban|Unban)\s+(?P<ip>\S+)'}],
        'keywords': {'ACTION': {'Ban', 'Unban'}, 'COMPONENT': {'jail', 'actions'}},
        'thematic_grouping': {
            'banned_ips': lambda log: log.get('action') == 'Ban',
            'unbanned_ips': lambda log: log.get('action') == 'Unban',
        },
        'session_field': 'ip', 'timestamp_format': None, 
    },
    'cisco_asa_firewall': {
        'name': 'Cisco ASA Firewall Log',
        'description': 'Logs from a Cisco ASA series firewall, typically via syslog.',
        'example': '%ASA-6-302013: Built inbound TCP connection 12345 for outside:192.0.2.100/1234 (192.0.2.100/1234) to inside:10.0.0.5/80 (10.0.0.5/80)',
        'detection_patterns': [r'%ASA-\d-\d+:', r'Built connection', r'Teardown TCP connection'],
        'parsing_rules': [
            {'type': 'connection', 'regex': r'%ASA-\d-(?P<event_code>\d+): (?P<action>Built|Teardown) (?P<protocol>\S+) connection \d+ for (?P<direction>inbound|outbound) .*? to (?P<dest_ip>\S+)/\d+.* from (?P<src_ip>\S+)/\d+'},
            {'type': 'access', 'regex': r'%ASA-\d-(?P<event_code>\d+): (?P<action>Deny|Permit) (?P<protocol>\S+) src .*?:(?P<src_ip>\S+)/\d+ dst .*?:(?P<dest_ip>\S+)/\d+'},
        ],
        'keywords': {'CONNECTION_MGMT': {'Built', 'Teardown'}, 'ACCESS_CONTROL': {'Deny', 'Permit'}},
        'thematic_grouping': {
            'denied_traffic': lambda log: log.get('action') == 'Deny',
            'inbound_connections': lambda log: log.get('direction') == 'inbound',
            'outbound_connections': lambda log: log.get('direction') == 'outbound',
        },
        'session_field': 'src_ip', 'timestamp_format': None,
    },
    
    # --- IDS / IPS Logs ---
    'suricata_eve_log': {
        'name': 'Suricata EVE JSON Log',
        'description': 'JSON-based output from the Suricata Intrusion Detection System.',
        'example': '{"timestamp":"2025-10-05T12:00:00.123456+0000","event_type":"alert","src_ip":"192.0.2.100", "dest_ip":"10.0.0.5", "alert":{"severity":1}}',
        'detection_patterns': [r'"event_type":\s*"alert"', r'"suricata":'],
        'parsing_rules': [{'type': 'suricata_event', 'is_json': True}],
        'keywords': {'EVENT_TYPE': {'alert', 'http', 'dns', 'flow', 'tls'}, 'SEVERITY': {'"severity": 1', '"severity": 2', '"severity": 3'}, 'NETWORK': {'src_ip', 'dest_ip', 'src_port', 'dest_port'}},
        'thematic_grouping': {
            'high_severity_alerts': lambda log: log.get('alert', {}).get('severity') == 1,
            'medium_severity_alerts': lambda log: log.get('alert', {}).get('severity') == 2,
            'dns_events': lambda log: log.get('event_type') == 'dns',
            'http_events': lambda log: log.get('event_type') == 'http',
            'tls_handshakes': lambda log: log.get('event_type') == 'tls',
            'file_transfers': lambda log: log.get('event_type') == 'fileinfo',
        },
        'session_field': 'src_ip', 'timestamp_format': 'iso',
    },
    'zeek_conn_log': {
        'name': 'Zeek (Bro) conn.log',
        'description': 'Connection logs from the Zeek Network Security Monitor.',
        'example': '1633449600.123456\tCxyz...\t192.0.2.100\t12345\t10.0.0.5\t80\ttcp\thttp\t5.0\t100\t200\tSF',
        'detection_patterns': [r'#separator \x09', r'#fields\s+ts\s+uid\s+id.orig_h'],
        'parsing_rules': [{'type': 'zeek_conn', 'regex': r'^(?P<ts>\d+\.\d+)\s+(?P<uid>\S+)\s+(?P<id_orig_h>\S+)\s+(?P<id_orig_p>\d+)\s+(?P<id_resp_h>\S+)\s+(?P<id_resp_p>\d+)\s+(?P<proto>\S+)\s+(?P<service>\S*)\s+(?P<duration>\S*)\s+(?P<orig_bytes>\S*)\s+(?P<resp_bytes>\S*)\s+(?P<conn_state>\S+)'}],
        'keywords': {'NETWORK': {'orig_h', 'resp_h', 'proto', 'service'}, 'STATE': {'conn_state'}},
        'thematic_grouping': {
            'long_connections': lambda log: float(log.get('duration', 0) or 0) > 300,
            'rejected_connections': lambda log: log.get('conn_state') == 'REJ',
            'dns_traffic': lambda log: log.get('service') == 'dns',
            'ssh_traffic': lambda log: log.get('service') == 'ssh',
        },
        'session_field': 'id_orig_h', 'timestamp_format': None, # Unix timestamp
    },
    'ossec_log': {
        'name': 'OSSEC HIDS Log',
        'description': 'Logs from the OSSEC Host-based Intrusion Detection System.',
        'example': '**Alert: 1633449600.12345; Rule: 5712 (level 5) -> "SSHD authentication failed."',
        'detection_patterns': [r'OSSEC HIDS \S+ Report', r'Rule: \d+ \(level \d+\) ->'],
        'parsing_rules': [{'type': 'ossec_alert', 'regex': r'\*\*Alert: \d+\.\d+; Rule: (?P<rule_id>\d+) \(level (?P<level>\d+)\) -> "(?P<description>.*?)"\n(?:.*Src IP: (?P<src_ip>\S+))?'}],
        'keywords': {'SEVERITY': {'level 7', 'level 8', 'level 9', 'level 10'}, 'ALERT': {'Rule', 'Alert'}},
        'thematic_grouping': {'high_level_alerts': lambda log: int(log.get('level', 0)) >= 10},
        'session_field': 'src_ip', 'timestamp_format': None,
    },

    # --- Database Logs ---
    'postgresql_log': {
        'name': 'PostgreSQL Log',
        'description': 'Logs from the PostgreSQL database server.',
        'example': '2025-10-05 12:00:00 UTC [12345] LOG:  duration: 1234.567 ms  statement: SELECT * FROM users;',
        'parsing_rules': [{'type': 'query', 'regex': r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \w+) \[\d+\] (?P<level>LOG|ERROR|FATAL): \s+(?:duration: (?P<duration>\d+\.\d+) ms\s+)?statement: (?P<statement>.*)'}],
        'keywords': {'QUERY_TYPE': {'SELECT', 'INSERT', 'UPDATE', 'DELETE'}, 'SEVERITY': {'ERROR', 'FATAL'}},
        'thematic_grouping': {
            'slow_queries': lambda log: float(log.get('duration', 0)) > 1000,
            'connection_errors': lambda log: 'FATAL' in log.get('level', ''),
            'ddl_statements': lambda log: any(kw in log.get('statement', '').upper() for kw in ['CREATE', 'ALTER', 'DROP']),
        },
        'session_field': None, 'timestamp_format': '%Y-%m-%d %H:%M:%S',
    },
    'mysql_slow_query_log': {
        'name': 'MySQL Slow Query Log',
        'description': 'Logs of SQL queries that took a long time to execute.',
        'example': '# Time: 251005 12:00:00\n# Query_time: 5.12345  Lock_time: 0.0001 Rows_sent: 1  Rows_examined: 100000\nSET timestamp=1633449600;\nSELECT * FROM large_table;',
        'parsing_rules': [{'type': 'slow_query', 'regex': r'^# Query_time: (?P<query_time>\d+\.\d+)\s+Lock_time: (?P<lock_time>\d+\.\d+)\s+Rows_sent: (?P<rows_sent>\d+)\s+Rows_examined: (?P<rows_examined>\d+)\nSET timestamp=\d+;\n(?P<statement>.*);'}],
        'keywords': {'PERFORMANCE': {'Query_time', 'Lock_time'}},
        'thematic_grouping': {'very_slow_queries': lambda log: float(log.get('query_time', 0)) > 10},
        'session_field': None, 'timestamp_format': None,
    },
    'redis_log': {
        'name': 'Redis Log',
        'description': 'Logs from the Redis in-memory data store.',
        'example': '12345:M 05 Oct 2025 12:00:00.000 * Ready to accept connections',
        'parsing_rules': [{'type': 'redis_event', 'regex': r'^\d+:\w+ (?P<timestamp>\d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2}\.\d{3}) (?P<level>\S) (?P<message>.*)'}],
        'keywords': {'PERSISTENCE': {'RDB', 'AOF'}, 'SERVER_EVENT': {'Ready to accept connections'}},
        'thematic_grouping': {'persistence_events': lambda log: 'Saving...' in log.get('message', '')},
        'session_field': None, 'timestamp_format': '%d %b %Y %H:%M:%S.%f',
    },

    # --- Cloud & DevOps Logs ---
    'aws_cloudtrail_log': {
        'name': 'AWS CloudTrail Log (JSON)',
        'description': 'API activity and events for an AWS account.',
        'example': '{"eventVersion":"1.08","userIdentity":{"arn":"arn:aws:iam::123:user/test"},"eventTime":"2025-10-05T12:00:00Z","eventName":"ConsoleLogin","awsRegion":"us-east-1","sourceIPAddress":"192.0.2.100"}',
        'detection_patterns': [r'"eventSource": "\S+\.amazonaws\.com"', r'"awsRegion":'],
        'parsing_rules': [{'type': 'aws_event', 'is_json': True}],
        'keywords': {'IDENTITY': {'userIdentity', 'sourceIPAddress'}, 'EVENT': {'eventName', 'eventSource'}, 'ERROR': {'errorCode'}},
        'thematic_grouping': {
            'console_logins': lambda log: log.get('eventName') == 'ConsoleLogin',
            'iam_changes': lambda log: log.get('eventSource') == 'iam.amazonaws.com',
            's3_activity': lambda log: log.get('eventSource') == 's3.amazonaws.com',
        },
        'session_field': 'sourceIPAddress', 'timestamp_format': 'iso',
    },
    'docker_log': {
        'name': 'Docker Container Log',
        'description': 'Standard output from a running Docker container.',
        'example': 'my-container | 2025-10-05T12:00:00.123456789Z This is a log message from the application.',
        'detection_patterns': [r'^\S{12}\s', r'^[a-zA-Z0-9\-_/]+\s'], 
        'parsing_rules': [{'type': 'container_out', 'regex': r'^(?P<container_id>\S+?)\s+(?P<message>.*)'}],
        'keywords': {}, 'thematic_grouping': {},
        'session_field': 'container_id', 'timestamp_format': None,
    },
    'git_log': {
        'name': 'Git Log Output',
        'description': 'Standard output from the `git log` command.',
        'example': 'commit a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\nAuthor: Example <email@example.com>\nDate:   Sun Oct 5 12:00:00 2025 -0400\n\n    feat: Add new feature',
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
    },
    'jenkins_log': {
        'name': 'Jenkins Log',
        'description': 'Console output from a Jenkins build job.',
        'example': '[Pipeline] echo\nHello World\n[Pipeline] }\nFinished: SUCCESS',
        'detection_patterns': [r'Started by user', r'Finished: (SUCCESS|FAILURE|ABORTED)'],
        'parsing_rules': [{'type': 'jenkins_step', 'regex': r'^(?:\[\S+\])?\s*(?P<message>.*)'}],
        'keywords': {'BUILD_STATUS': {'SUCCESS', 'FAILURE', 'ABORTED'}, 'BUILD_STEP': {'Archiving artifacts', 'Cloning', 'Checking out'}},
        'thematic_grouping': {'build_failures': lambda log: 'Finished: FAILURE' in log.get('message', '')},
        'session_field': None, 'timestamp_format': None,
    },

    # --- Application Logs ---
    'rabbitmq_log': {
        'name': 'RabbitMQ Log',
        'description': 'Logs from the RabbitMQ message broker.',
        'example': '=INFO REPORT==== 2025-10-05 12:00:00 ===\naccepting AMQP connection <0.123.0> (127.0.0.1:12345 -> 127.0.0.1:5672)',
        'detection_patterns': [r'=INFO REPORT====', r'starting TCP connection'],
        'parsing_rules': [{'type': 'rabbitmq_event', 'regex': r'^(?P<level>=INFO|=WARNING|=ERROR) REPORT==== (?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ===\n(?P<message>(?:.|\n)*?)(?=\n=... REPORT|\Z)'}],
        'keywords': {'CONNECTION': {'connection', 'accepting', 'closing'}, 'ERROR': {'ERROR REPORT'}},
        'thematic_grouping': {'connection_events': lambda log: 'connection' in log.get('message', '')},
        'session_field': None, 'timestamp_format': '%Y-%m-%d %H:%M:%S',
    },
     'microsoft_exchange_log': {
        'name': 'Microsoft Exchange Log (SMTP)',
        'description': 'SMTP protocol logs from MS Exchange Server.',
        'example': '2025-10-05T12:00:00.123Z,MAILSERVER\\Default Frontend,08D88...,0,10.0.0.1:25,192.0.2.100:12345,>,EHLO,contoso.com',
        'detection_patterns': [r'#Software: Microsoft Exchange Server', r'#Fields: date-time,connector-id,session-id'],
        'parsing_rules': [{'type': 'smtp_event', 'regex': r'^(?P<timestamp>[^,]+),(?P<connector_id>[^,]+),(?P<session_id>[^,]+),(?P<sequence_number>\d+),(?P<local_endpoint>[^,]+),(?P<remote_endpoint>[^,]+),(?P<event>[^,]+),(?P<data>[^,]+)'}],
        'keywords': {'SMTP_VERB': {'EHLO', 'MAIL FROM', 'RCPT TO', 'DATA'}, 'DIRECTION': {'<', '>'}},
        'thematic_grouping': {'inbound_mail': lambda log: log.get('event') == '>,MAIL FROM'},
        'session_field': 'session_id', 'timestamp_format': 'iso',
    },

    # --- Generic & Developer Logs ---
    'python_traceback': {
        'name': 'Python Application Traceback',
        'description': 'Standard error output from Python applications.',
        'example': 'Traceback (most recent call last):\n  File "test.py", line 10, in <module>\n    raise ValueError("An example error")',
        'detection_patterns': [r'Traceback \(most recent call last\):', r'File ".*?", line \d+, in'],
        'parsing_rules': [
            {'type': 'error_header', 'regex': r'^(?P<traceback>Traceback \(most recent call last\):)'},
            {'type': 'file_path', 'regex': r'^\s+File "(?P<file_path>.*?)", line (?P<line_number>\d+), in (?P<function>.*)'},
            {'type': 'error_message', 'regex': r'^(?P<error_type>\w+Error): (?P<error_message>.*)'},
        ],
        'keywords': {'ERROR_CONTEXT': {'Traceback', 'File', 'line'}, 'ERROR_TYPE': {'ValueError', 'TypeError', 'KeyError'}},
        'thematic_grouping': {}, 'session_field': None, 'timestamp_format': None,
    },
    'json_log': {
        'name': 'JSON Log Format',
        'description': 'Logs where each line is a self-contained JSON object.',
        'example': '{"timestamp": "2025-10-05T12:00:00.123Z", "level": "error", "message": "Failed to connect to database."}',
        'detection_patterns': [r'^{.*"level":.*}$', r'^{.*"timestamp":.*}$'],
        'parsing_rules': [{'type': 'json_entry', 'is_json': True}],
        'keywords': {'SEVERITY': {'level', 'severity'}, 'METADATA': {'timestamp', 'hostname'}, 'ERROR': {'error', 'exception'}},
        'thematic_grouping': {'errors': lambda log: log.get('level', '').lower() in ['error', 'critical', 'fatal']},
        'session_field': 'hostname', 'timestamp_format': 'iso',
    },
    'generic': { 
        'name': 'Generic Text File',
        'description': 'A generic profile for unrecognized text files.',
        'detection_patterns': [], 'parsing_rules': [{'type': 'generic', 'regex': r'^(?P<line_content>.*)'}],
        'keywords': {}, 'thematic_grouping': {}, 'session_field': None, 'timestamp_format': None,
    }
}
