# Getting Started with Log Analyzer AI

## Quick Setup (5 minutes)

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Get API Keys (Optional but Recommended)

#### VirusTotal API

- Go to: https://www.virustotal.com/gui/home/upload
- Create free account
- Copy API key from Settings

#### AbuseIPDB API

- Go to: https://www.abuseipdb.com
- Create free account
- Copy API key from Account → API

### 3. Configure API Keys

```bash
# Edit .env file with your keys
VT_API_KEY=your_key_here
ABUSE_API_KEY=your_key_here
```

### 4. Prepare Your Data

Place CSV file in `data/logs.csv` with columns:

- Source IP
- Destination IP
- Port

### 5. Run Analysis

```bash
python main.py
```

## Next Steps

1. Review README.md for detailed documentation
2. Check sample logs in data/logs.csv
3. Explore rules in src/rules.py
4. Customize rules for your needs
5. Export results for incident response

## Troubleshooting

### No API Keys?

The app works without API keys (limited functionality). Add them to .env to enable full enrichment.

### Want to test without APIs?

The classification engine will still work with local rules based on known IP ranges.

### Common Issues?

See README.md → Troubleshooting section

## Architecture Overview

```
CSV Logs
    ↓
[Parser] - Extract IPs
    ↓
[Enricher] - Fetch threat data (VirusTotal, AbuseIPDB)
    ↓
[Cache] - Store results (avoid repeated API calls)
    ↓
[RuleEngine] - Classify IPs (intelligent rules)
    ↓
[ReportGenerator] - Beautiful formatted output
```

## Key Features

✅ Multi-source threat intelligence
✅ Intelligent IP classification
✅ Caching for performance
✅ Comprehensive error handling
✅ Beautiful colored reports
✅ Logging for auditing
✅ Modular and extensible

## Support

For detailed help, see README.md
