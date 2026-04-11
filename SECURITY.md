# Security Policy

## Overview

`fluttersupabasehelper` is a static security and configuration analysis CLI designed to identify common anti-patterns in Flutter + Supabase applications.

## Important Limitations

* This is a **static checker**, NOT a full cybersecurity audit tool.
* It does not act dynamically to discover hidden vulnerabilities if they fall outside its pre-defined heuristic rule boundaries.
* Zero findings does NOT guarantee that your software is immune to breaches or conceptually architected correctly. You are solely responsible for your own codebase's security.

## Reporting a Vulnerability

If you find a new pattern that exposes credentials or bypasses existing detector rules, please open an Issue on GitHub highlighting the gap instead of using standard responsible disclosure channels, since this tool is exclusively an open-code evaluation framework.

If you discover a structural runtime exploit *inside* the scanner itself, open an Issue.
