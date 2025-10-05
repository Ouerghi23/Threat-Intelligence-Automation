# Threat-Intelligence-Automation

Automated threat analysis workflow using n8n that detects, analyzes, and reports on potential security threats (IPs, URLs, domains, hashes) using multiple threat intelligence sources.

## 🌟 Features

- **Auto-Detection**: Automatically identifies the type of indicator (IP, URL, Domain, Hash)
- **Multi-Source Intelligence**: 
  - AlienVault OTX (Open Threat Exchange)
  - VirusTotal API
- **AI-Powered Analysis**: ChatGPT-4o integration for intelligent threat assessment
- **Risk Scoring**: Automated 0-100 risk score calculation with severity levels
- **Real-time Alerts**: Telegram notifications for critical threats
- **Threat Logging**: Automatic logging to Google Sheets for incident tracking

## 📊 Workflow Overview

```
Input → Auto-Detect → Route by Type → OTX/VT Analysis → 
Risk Calculation → AI Enrichment → Alert/Log
```

### Risk Levels

| Score | Level | Severity | Action |
|-------|-------|----------|--------|
| 80-100 | 🔴 CRITICAL | CRITICAL | Immediate action required |
| 50-79 | 🔴 MALICIOUS | HIGH | Action required |
| 25-49 | 🟠 SUSPICIOUS | MEDIUM | Investigation needed |
| 10-24 | 🟡 LOW RISK | LOW | Monitor |
| 0-9 | 🟢 SAFE | LOW | No action |

## 🔧 Prerequisites

- n8n instance (self-hosted or cloud)
- API Keys:
  - AlienVault OTX API key
  - VirusTotal API key
  - OpenAI API key
  - Telegram Bot token
  - Google Sheets OAuth2 credentials

## 📦 Installation

### 1. Clone or Import Workflow

Import the workflow JSON into your n8n instance:
- Go to n8n → Workflows → Import from File
- Select the workflow JSON file

### 2. Configure Credentials

#### AlienVault OTX
```
Node: "Analyse OTX1"
Header: X-OTX-API-KEY
Value: YOUR_OTX_API_KEY
```

#### VirusTotal
```
Node: "Analyse VirusTotal1"
Credential Type: VirusTotal API
API Key: YOUR_VIRUSTOTAL_API_KEY
```

#### OpenAI
```
Node: "Enrichissement AI1"
Credential Type: OpenAI API
API Key: YOUR_OPENAI_API_KEY
Model: chatgpt-4o-latest
```

#### Telegram
```
Node: "Alerte Telegram1"
Credential Type: Telegram API
Bot Token: YOUR_TELEGRAM_BOT_TOKEN
Chat ID: YOUR_CHAT_ID
```

#### Google Sheets
```
Node: "Google Sheets1"
Credential Type: Google Sheets OAuth2
Setup OAuth2 connection with Google
```

### 3. Update Configuration

**Input Node** (`Configuration Entrée1`):
```json
{
  "value": "YOUR_INDICATOR_HERE"
}
```

Supported formats:
- IP: `8.8.8.8`
- URL: `https://example.com`
- Domain: `example.com`
- Hash: MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars)

**Google Sheets**:
- Update the spreadsheet URL in `Google Sheets1` node
- Sheet name: `n8n-sheet` (or customize)

## 🚀 Usage

### Manual Trigger
1. Update the `value` in `Configuration Entrée1` node
2. Click "Execute workflow"
3. View results in execution log

### Webhook Trigger (Optional)
Convert `When clicking 'Execute workflow'` to a Webhook node:
```
POST /webhook/threat-intel
{
  "value": "8.8.8.8"
}
```

### Scheduled Analysis (Optional)
Add a Schedule Trigger node to analyze indicators from a queue or database.

## 📋 Output Format

### Telegram Alert Example
```
🚨 ALERTE SÉCURITÉ 🚨

🔴 MALICIOUS - Score: 65/100

📋 Type: IP
🎯 Cible: 192.168.1.1
⚠️ Sévérité: HIGH
⏰ Détecté: 2025-10-05T10:30:00.000Z

📊 Analyse AI:
This IP has been flagged by multiple threat intelligence sources...

🔍 Détails Techniques:
• OTX Pulses: 3
• VT Malicious: 5
• VT Suspicious: 2
• Réputation: -10

💡 Recommandations:
- Block this IP at the firewall level
- Review recent access logs
- Monitor for similar indicators
```

### Google Sheets Columns
- `type`, `value`, `timestamp`
- `risk_score`, `risk_level`, `severity`
- `details` (JSON)
- `ai_analysis`, `ai_recommendations`
- `raw_otx`, `raw_vt` (truncated to 5000 chars)

## 🔒 Security Notes

- **Never commit API keys** to version control
- Store credentials in n8n's credential manager
- Use environment variables for sensitive data
- Limit API rate limits to avoid throttling
- Review data retention policies for logged threats

## 🛠️ Customization

### Adjust Risk Scoring
Edit `Calcul Risque1` node to modify scoring algorithm:
```javascript
risk_score += otx_pulses * 25; // Adjust multiplier
risk_score += vt_malicious * 15;
risk_score += vt_suspicious * 8;
```

### Modify AI Prompt
Edit `Enrichissement AI1` node to change analysis style:
```
Tu es un expert SOC. Analyse cette menace...
```

### Add More Sources
Integrate additional threat intel sources:
- AbuseIPDB
- Shodan
- URLScan.io
- Hybrid Analysis

## 📈 Performance Tips

- Enable workflow caching for repeated indicators
- Use batching for bulk analysis
- Implement rate limiting for API calls
- Consider async execution for large volumes

## 🐛 Troubleshooting

**API Rate Limits**:
- OTX: Check your subscription tier
- VirusTotal: Free tier = 4 requests/minute
- OpenAI: Monitor token usage

**Missing Data**:
- Verify API keys are valid
- Check indicator format (IP, URL, domain, hash)
- Review error logs in n8n execution history

**Telegram Not Sending**:
- Verify bot token and chat ID
- Ensure bot has permissions to send messages
- Check message length (Telegram limit: 4096 chars)

## 📝 License

This workflow is provided as-is for educational and operational use.

## 🤝 Contributing

Contributions welcome! Please submit issues or pull requests with improvements.

## 📞 Support

For issues or questions:
- Open an issue on GitHub
- Check n8n documentation: https://docs.n8n.io
- Review API documentation for integrated services

---
