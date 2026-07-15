# Project Context: External Exposure Monitor

## Goal
A lightweight OSINT-based spin-off of EASM for organizations using Splunk.
Monitors an organization's known public IP ranges, uses Shodan InternetDB to collect exposed services, normalizes them, and sends the events to Splunk HEC for alerting and dashboards.

## Architecture
1. **Asset Inventory**: `config/assets.yaml` defines targets (IPs/CIDRs).
2. **Collector**: Loops through targets, queries Shodan.
3. **Normalizer & Baseline**: Formats the OSINT data and compares against a baseline to only flag *new* exposures.
4. **Splunk HEC**: Dispatches events to Splunk index.

## Rules & Principles
- **Ponytail Mode**: YAGNI, standard library first, zero boilerplate, minimalistic code.
- **Loop Engineering**: Develop -> Test -> Verify -> Continue.
