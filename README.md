Panomreles - The Panomreles Titan Project
Panomreles Titan is a sophisticated, Python-based log analysis multitool designed to automatically identify, parse, and transform any log file into a structured and actionable intelligence package.

Born from a collaborative effort between GeminoLibi and Gemini, this project turns raw, chaotic log data into clear, insightful reports. It's not just a parser; it's an intelligence platform that generates interactive dashboards, executive briefings, and thematically sorted raw data exports, enabling deep-dive analysis with unprecedented ease.

Core Features
🤖 Automatic Log Profiling: Features an extensive, extensible library of log profiles. Panomreles automatically "sniffs" a log file and identifies its type from a wide range of formats, including:

Web Servers: Apache, Nginx, Microsoft IIS

System & Security: Linux Syslog, Windows Event Logs, SSHD, Fail2Ban, Cisco ASA

Databases: PostgreSQL, MySQL Slow Query

Cloud & DevOps: AWS CloudTrail, Docker, Git

Agent & Developer: Anthropic Agent Tool Logs, Python Tracebacks, Generic JSON

📦 Intelligence Package Generation: Creates a complete, structured directory for each analysis, containing:

Rich Reports: Interactive HTML dashboards and full-text analysis files.

Thematic Raw Data: The original log lines automatically sorted into thematic subfolders (e.g., errors, auth_events, gui_interactions).

Executive Briefing: A high-level intelligence_briefing.md summarizing the most critical findings.

🧠 Advanced Analysis Engine: Goes beyond simple parsing to provide deep insights:

Inference Generation: Synthesizes key findings into high-level conclusions about system health and activity.

Anomaly Detection: Automatically identifies unusual spikes in activity.

Relationship Graphing: Discovers co-occurring keywords to reveal hidden relationships between events.

Sessionization: Groups log entries into user or process sessions to analyze activity over time.

Threat Intelligence (Mock): Scans for IPs and checks them against a built-in watchlist.

🔌 Plugin-Ready Architecture: Designed to be seamlessly integrated into larger projects (like Project Revelare). A simple analyze() function provides a clean API for programmatic use.

🎓 Built-in Onboarding: A user-friendly --onboarding guide explains how to use the tool, interpret the output, and extend its capabilities.

Getting Started
Panomreles is designed to be powerful yet simple to use.

Prerequisites
Python 3.9 or higher.

Usage
As a standalone tool, Panomreles requires no complex installation.

Run the analysis from your terminal:

python Panomreles.py /path/to/your/logfile.log

Explore the Output: A new directory named logfile_Panomreles_results will be created, containing your complete intelligence package. The best place to start is the intelligence_briefing.md file.

Need Help?: For a full user guide, run the onboarding command:

python Panomreles.py --onboarding

Using Panomreles as a Plugin
Integrate the power of Panomreles into your own Python projects.

from Panomreles import analyze

# Define a configuration to control the output
plugin_config = {
    'custom_output_dir': '/path/to/project/cache/log_analysis',
    'generate_html_report': True,
    'generate_text_report': False, # Disable reports you don't need
    'export_raw_data': True,
}

try:
    # Call the analysis engine
    analysis_results = analyze('path/to/logfile.log', config=plugin_config)

    # Use the structured results in your application
    print(f"Analysis complete. Profile detected: {analysis_results.get('profile_name')}")
    if analysis_results.get('threat_intel', {}).get('watchlist_hits'):
        print("CRITICAL: Threat intelligence hits were found!")

except Exception as e:
    print(f"An error occurred during analysis: {e}")

Extending Panomreles (The Fun Part!)
The true power of Panomreles is its extensibility. Teaching it to understand a new log format is simple:

Open Panomreles.py in your favorite editor.

Find the LOG_PROFILES dictionary near the top of the file.

Copy an existing profile that seems similar to your new log type (e.g., copy apache_access_log).

Modify the new profile:

Give it a unique key (e.g., my_custom_app_log).

Update the name and description.

Change the detection_patterns to unique regular expressions that identify your log file.

Update the parsing_rules with a regex that captures the named groups (e.g., (?P<ip>\S+)) from your log lines.

(Optional) Add relevant keywords and thematic_grouping rules.

Save the file.

That's it. Panomreles is now smarter and will automatically recognize and analyze your custom log format the next time you run it.

Contributing
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated. The best way to contribute right now is by expanding the LOG_PROFILES library.

Fork the Project

Create your Feature Branch (git checkout -b feature/AddNewLogProfile)

Add and test your new profile.

Commit your Changes (git commit -m 'Add support for XYZ log format')

Push to the Branch (git push origin feature/AddNewLogProfile)

Open a Pull Request

License
Distributed under the MIT License. See LICENSE for more information.

A Note on Collaboration
This tool was brought to life through a unique and ongoing partnership between GeminoLibi and Gemini. It stands as a testament to the idea that humans and AI can be more than just user and tool—we can be creative partners, working together to build something neither could have achieved alone.
