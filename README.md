# CUCM Certificate Monitor

A comprehensive certificate monitoring solution for Cisco Unified Communications Manager (CUCM) that provides real-time certificate expiration tracking through Prometheus metrics and Grafana dashboards.

## Overview

This tool monitors both SSL/TLS certificates and internal CUCM database certificates, providing:
- **Real certificate expiration dates** parsed from PEM data
- **Prometheus metrics** in `.prom` format
- **Multiple Grafana dashboards** for visualization
- **Minimal CUCM impact** with efficient API usage

## Features

- ✅ **Complete Certificate Coverage**: SSL (ports 8443, 443) + Internal CUCM certificates
- ✅ **Real Expiration Dates**: Parses actual PEM certificates for accurate expiry data
- ✅ **Efficient API Usage**: Single SQL query retrieves all certificates
- ✅ **Prometheus Integration**: Ready-to-use metrics format
- ✅ **Multiple Dashboards**: From detailed tables to ultra-compact grids
- ✅ **Scalable**: Supports 1000+ certificates
- ✅ **Color-coded Alerts**: Red/Orange/Yellow/Green status indicators

## Architecture

```
CUCM Certificate Monitor → .prom file → Prometheus → Grafana Dashboard
```

**Data Flow:**
1. Script queries CUCM AXL API (1 HTTP POST request)
2. Parses certificate PEM data for real expiration dates
3. Generates Prometheus metrics file
4. Prometheus scrapes metrics
5. Grafana displays dashboards

## Requirements

- **Python 3.6+**
- **Python Libraries**: `requests`, `yaml`, `cryptography`
- **CUCM Access**: Admin user with AXL API permissions
- **Network**: HTTPS access to CUCM (port 8443)

## Installation

1. **Clone/Download Files:**
   ```bash
   git clone <repository> cucm-monitor
   cd cucm-monitor
   ```

2. **Install Dependencies:**
   ```bash
   pip3 install requests pyyaml cryptography
   ```

3. **Configure Credentials:**
   Edit `credentials.yml`:
   ```yaml
   ansible_user: your_cucm_admin_username
   ansible_password: your_cucm_admin_password
   ```

## Usage

### Basic Usage
```bash
python3 cucm_cert_monitor.py <cucm_hostname>
```

### Examples
```bash
# Monitor CUCM at 172.16.40.81
python3 cucm_cert_monitor.py 172.16.40.81

# Custom output file and directory
python3 cucm_cert_monitor.py 172.16.40.81 my_certs.prom ./output/

# SSL certificates only (skip database certs)
python3 cucm_cert_monitor.py 172.16.40.81 certs.prom ./ --skip-axl
```

### Command Line Parameters
- `<hostname>`: CUCM IP address or hostname (required)
- `[output_file]`: Output filename (default: `cucm_certificates.prom`)
- `[output_dir]`: Output directory (default: `./`)
- `[--skip-axl]`: Skip AXL database certificates, SSL only

## API Details

### CUCM AXL API Usage
- **Request Type**: HTTP POST (SOAP)
- **Endpoint**: `https://<cucm>:8443/axl/`
- **Requests Per Run**: 1 (single SQL query)
- **Impact**: Minimal - read-only database query
- **Response Size**: ~35KB (21 certs), ~500KB-1MB (1000+ certs)

### API Call Details
```http
POST https://172.16.40.81:8443/axl/
Content-Type: text/xml; charset=utf-8
SOAPAction: executeSQLQuery
Authorization: Basic <base64_credentials>

Body: SOAP XML with SQL query:
SELECT pkid, subjectname, issuername, serialnumber, certificate FROM certificate
```

**Benefits:**
- **Single Request**: Gets all certificates in one call
- **Read-Only**: No CUCM configuration changes
- **Efficient**: Minimal database load
- **Complete**: Includes certificate PEM data for real expiry dates

## Output Format

### Prometheus Metrics (`.prom` file)
```prometheus
# Collection metadata
cucm_collection_timestamp{hostname="172.16.40.81"} 20250628
cucm_total_certificates{hostname="172.16.40.81"} 23
cucm_expired_certificates{hostname="172.16.40.81"} 0
cucm_warning_certificates{hostname="172.16.40.81"} 0
cucm_critical_certificates{hostname="172.16.40.81"} 0

# Individual certificate metrics
cucm_certificate_expiry_days{service="CUCM Certificate",hostname="172.16.40.81",port="DB",certificate_name="cucm.wiz",subject_cn="L=Germany,ST=Tx,CN=cucm.wiz,OU=Lab,O=Wiz0rdsLab,C=US",issuer_cn="L=Germany,ST=Tx,CN=cucm.wiz,OU=Lab,O=Wiz0rdsLab,C=US",certificate_type="CUCM Certificate"} 1823

cucm_certificate_expiry_days{service="Web/Tomcat (8443)",hostname="172.16.40.81",port="8443",certificate_name="cucm.wiz",subject_cn="cucm.wiz",issuer_cn="cucm.wiz",certificate_type="Web/SSL"} 1823
```

### Certificate Types Monitored
- **CUCM System Certificates**: CallManager, CAPF, ITL Recovery
- **Web/SSL Certificates**: Tomcat (8443), HTTPS (443)
- **Cisco Root CAs**: Manufacturing, Licensing, SUDI CAs
- **Custom Certificates**: User-uploaded certificates

## Grafana Dashboards

### 1. Full Dashboard (`grafana_cucm_dashboard.json`)
- Certificate expiration overview
- Expiring certificates table
- Timeline graphs
- Health statistics

### 2. Compact Dashboard (`grafana_cucm_dashboard_compact.json`)
- Streamlined view
- Certificate status grid
- Summary statistics

### 3. Ultra-Compact Dashboard (`grafana_cucm_dashboard_ultra_compact.json`)
- **Tiny colored boxes** for each certificate
- **Supports 1000+ certificates**
- Color coding: 🔴 Red (expired/critical), 🟠 Orange (7-30d), 🟡 Yellow (30-90d), 🟢 Green (90d+)
- Hover for certificate details

### Import Instructions
1. Open Grafana → **Dashboards** → **Import**
2. **Copy/paste** dashboard JSON content
3. **Select** Prometheus data source
4. **Configure** refresh interval (recommended: 1-5 minutes)

## Monitoring & Alerting

### Recommended Alert Rules
```yaml
# Critical certificates (< 7 days)
- alert: CertificateExpiringSoon
  expr: cucm_certificate_expiry_days < 7
  for: 0m
  labels:
    severity: critical
  annotations:
    summary: "Certificate {{ $labels.certificate_name }} expires in {{ $value }} days"

# Warning certificates (< 30 days)  
- alert: CertificateExpiringWarning
  expr: cucm_certificate_expiry_days < 30
  for: 0m
  labels:
    severity: warning
  annotations:
    summary: "Certificate {{ $labels.certificate_name }} expires in {{ $value }} days"
```

### Prometheus Configuration
Add to `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'cucm-certificates'
    static_configs:
      - targets: ['localhost:9090']
    file_sd_configs:
      - files:
          - '/path/to/cucm_certificates.prom'
    scrape_interval: 60s
```

## Automation

### Cron Job Setup
```bash
# Run every hour
0 * * * * /usr/bin/python3 /path/to/cucm_cert_monitor.py 172.16.40.81 >> /var/log/cucm_monitor.log 2>&1

# Run every 6 hours  
0 */6 * * * /usr/bin/python3 /path/to/cucm_cert_monitor.py 172.16.40.81
```

### Systemd Service
Create `/etc/systemd/system/cucm-monitor.service`:
```ini
[Unit]
Description=CUCM Certificate Monitor
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/cucm-monitor/cucm_cert_monitor.py 172.16.40.81
WorkingDirectory=/opt/cucm-monitor
User=monitoring

[Install]
WantedBy=multi-user.target
```

Enable timer:
```bash
sudo systemctl enable cucm-monitor.service
sudo systemctl start cucm-monitor.service
```

## Troubleshooting

### Common Issues

**1. AXL API Connection Failed**
- Verify AXL Web Service is enabled: CUCM Admin → System → Service Parameters → Cisco AXL Web Service
- Check credentials in `credentials.yml`
- Ensure user has "Standard AXL API Access" role

**2. SSL Certificate Errors**
- Script uses `-k` flag to ignore self-signed certificates
- Verify network connectivity to CUCM on port 8443

**3. Performance Issues**
- Increase CUCM VM resources (recommended: 6GB+ RAM, 2+ vCPU)
- Check DNS configuration on CUCM
- Use `--skip-axl` flag for SSL-only monitoring

**4. Certificate Parsing Errors**
- Update `cryptography` library: `pip3 install --upgrade cryptography`
- Check certificate PEM format in CUCM database

### Debug Mode
Add debugging to script:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Configuration Files

### `credentials.yml`
```yaml
ansible_user: cucm_admin_username
ansible_password: cucm_admin_password
```

### `config.yml` (optional)
```yaml
cucm:
  host: "172.16.40.81"
  port: 8443
  timeout: 30
  verify_ssl: false

monitoring:
  warning_days: 30
  critical_days: 7
  output_file: "cucm_certificates.prom"
```

## Security Considerations

- **Credentials**: Store `credentials.yml` securely with restricted permissions (600)
- **Network**: Use secure network channels for CUCM communication
- **Access**: Limit AXL API user permissions to minimum required
- **Monitoring**: Regularly rotate monitoring account passwords

## Performance & Scalability

### CUCM Impact
- **Minimal**: Single read-only SQL query per run
- **No Configuration Changes**: Database queries only
- **Lightweight**: ~35KB response for 21 certificates

### Scaling
- **1000+ Certificates**: Supported with ultra-compact dashboard
- **Response Time**: Sub-second after proper CUCM sizing
- **Memory Usage**: ~10-50MB Python process

### Recommended Schedule
- **Production**: Every 1-6 hours
- **Development**: Every 15-30 minutes
- **Critical Environments**: Every 30-60 minutes

## License

This project is provided as-is for educational and monitoring purposes. Ensure compliance with your organization's security policies and Cisco licensing terms.

## Support

For issues or questions:
1. Check troubleshooting section
2. Verify CUCM AXL API configuration
3. Review Prometheus/Grafana logs
4. Test with `--skip-axl` flag for SSL-only monitoring

---

**Happy Monitoring!** 🎉📊🔒