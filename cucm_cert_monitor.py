#!/usr/bin/env python3

import subprocess
import datetime
import sys
import os
import requests
import yaml
import base64
from pathlib import Path
from xml.etree import ElementTree as ET
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_certificate_via_openssl(hostname, port=8443):
    """Get certificate info using openssl command"""
    try:
        # Get certificate dates
        cmd = f"echo | openssl s_client -connect {hostname}:{port} -servername {hostname} 2>/dev/null | openssl x509 -noout -dates"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            return None
            
        # Parse the output
        dates = {}
        for line in result.stdout.strip().split('\n'):
            if line.startswith('notBefore='):
                dates['notBefore'] = line.replace('notBefore=', '')
            elif line.startswith('notAfter='):
                dates['notAfter'] = line.replace('notAfter=', '')
        
        if 'notAfter' not in dates:
            return None
            
        # Get certificate subject and issuer
        cmd2 = f"echo | openssl s_client -connect {hostname}:{port} -servername {hostname} 2>/dev/null | openssl x509 -noout -subject -issuer"
        result2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True)
        
        subject_cn = "Unknown"
        issuer_cn = "Unknown"
        
        if result2.returncode == 0:
            for line in result2.stdout.strip().split('\n'):
                if line.startswith('subject='):
                    # Extract CN from subject - handle "CN = value" format
                    subject_line = line.replace('subject=', '')
                    if 'CN = ' in subject_line:
                        cn_part = subject_line.split('CN = ')[1]
                        subject_cn = cn_part.split(',')[0].strip()
                    elif 'CN=' in subject_line:
                        cn_part = subject_line.split('CN=')[1]
                        subject_cn = cn_part.split(',')[0].strip()
                elif line.startswith('issuer='):
                    # Extract CN from issuer - handle "CN = value" format  
                    issuer_line = line.replace('issuer=', '')
                    if 'CN = ' in issuer_line:
                        cn_part = issuer_line.split('CN = ')[1]
                        issuer_cn = cn_part.split(',')[0].strip()
                    elif 'CN=' in issuer_line:
                        cn_part = issuer_line.split('CN=')[1]
                        issuer_cn = cn_part.split(',')[0].strip()
        
        # Parse expiry date and calculate days
        try:
            expiry_date = datetime.datetime.strptime(dates['notAfter'], '%b %d %H:%M:%S %Y %Z')
        except ValueError:
            try:
                expiry_date = datetime.datetime.strptime(dates['notAfter'], '%b %d %H:%M:%S %Y GMT')
            except ValueError:
                return None
                
        days_until_expiry = (expiry_date - datetime.datetime.now()).days
        
        # Label web certificates properly
        if port == 8443:
            service_name = 'Web/Tomcat (8443)'
        elif port == 443:
            service_name = 'Web/HTTPS (443)'
        else:
            service_name = f'SSL-{port}'
            
        return {
            'hostname': hostname,
            'port': port,
            'service_name': service_name,
            'certificate_name': subject_cn,
            'subject_cn': subject_cn,
            'issuer_cn': issuer_cn,
            'expiry_date': dates['notAfter'],
            'days_until_expiry': days_until_expiry,
            'certificate_type': 'Web/SSL'
        }
        
    except Exception as e:
        print(f"Error getting certificate for {hostname}:{port} - {e}")
        return None

def get_certificates_via_axl(hostname):
    """Get certificates from CUCM using AXL SOAP API"""
    certificates = []
    
    try:
        # Load credentials
        with open('credentials.yml', 'r') as f:
            creds = yaml.safe_load(f)
        
        username = creds['ansible_user']
        password = creds['ansible_password']
        
        # Try different ports and versions for AXL - focus on 14.0 since it worked
        axl_configs = [
            {'port': 8443, 'version': '14.0'}
        ]
        
        print(f"Checking CUCM database certificates via AXL...")
        
        for config in axl_configs:
            port = config['port']
            version = config['version']
            url = f"https://{hostname}:{port}/axl/"
            
            print(f"  Trying AXL on port {port} with API version {version}...")
            
            # SOAP envelope for SQL query to get only certificates assigned to services
            soap_body = f'''<?xml version="1.0" encoding="UTF-8"?>
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                              xmlns:ns="http://www.cisco.com/AXL/API/{version}">
                <soapenv:Header/>
                <soapenv:Body>
                    <ns:executeSQLQuery>
                        <sql>SELECT pkid, subjectname, issuername, serialnumber, certificate FROM certificate</sql>
                    </ns:executeSQLQuery>
                </soapenv:Body>
            </soapenv:Envelope>'''
            
            headers = {
                'Content-Type': 'text/xml; charset=utf-8',
                'SOAPAction': 'executeSQLQuery'
            }
            
            try:
                response = requests.post(
                    url,
                    data=soap_body,
                    headers=headers,
                    auth=(username, password),
                    verify=False,
                    timeout=10
                )
                
                if response.status_code == 200:
                    print(f"    SUCCESS on port {port} with version {version}!")
                    break
                else:
                    print(f"    Port {port} v{version}: Status {response.status_code}")
                    continue
                    
            except Exception as e:
                print(f"    Port {port} v{version}: {str(e)[:50]}...")
                continue
        else:
            print(f"  All AXL attempts failed")
            return certificates
        
        if response.status_code == 200:
            print(f"    Response length: {len(response.content)} bytes")
            root = ET.fromstring(response.content)
            
            # Parse SOAP response for SQL query data 
            namespaces = [
                f'.//{{{f"http://www.cisco.com/AXL/API/{version}"}}}row',
                './/row',
                './/*[local-name()="row"]'
            ]
            
            cert_elements = []
            for namespace in namespaces:
                cert_elements = root.findall(namespace)
                print(f"    Trying namespace: {namespace} - found {len(cert_elements)} elements")
                if cert_elements:
                    break
            
            for cert_elem in cert_elements:
                # Get certificate elements from SQL query response
                subject_elem = cert_elem.find('.//subjectname')
                issuer_elem = cert_elem.find('.//issuername')
                serial_elem = cert_elem.find('.//serialnumber')
                cert_pem_elem = cert_elem.find('.//certificate')
                
                if subject_elem is not None and cert_pem_elem is not None:
                    subject = subject_elem.text if subject_elem.text else 'Unknown'
                    issuer = issuer_elem.text if issuer_elem is not None and issuer_elem.text else 'Unknown'
                    serial = serial_elem.text if serial_elem is not None and serial_elem.text else 'Unknown'
                    cert_pem = cert_pem_elem.text if cert_pem_elem.text else None
                    
                    # Filter out Cisco root/manufacturing CAs and trust anchors (not applied to services)
                    skip_patterns = [
                        'Cisco Root CA', 'Cisco Manufacturing CA', 'SUDI CA', 
                        'Cisco Licensing Root CA', 'IdenTrust', 'Cisco Basic Assurance'
                    ]
                    
                    # Extract CN from subject for name
                    name = 'Unknown'
                    if 'CN=' in subject:
                        cn_part = subject.split('CN=')[1]
                        name = cn_part.split(',')[0].strip()
                    
                    # Skip certificates that match exclusion patterns (trust anchors, not service certs)
                    if any(pattern in name for pattern in skip_patterns):
                        continue
                    
                    # Determine service name based on certificate name patterns
                    if 'CAPF-' in name:
                        service_name = 'CAPF'
                    elif 'ITLRECOVERY' in name:
                        service_name = 'ITL-Recovery'
                    else:
                        service_name = 'CallManager'
                    
                    # Parse PEM certificate to extract expiration date
                    expiry_date = None
                    days_until_expiry = 9999
                    
                    if cert_pem and '-----BEGIN CERTIFICATE-----' in cert_pem:
                        try:
                            # Parse the PEM certificate using cryptography library
                            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                            expiry_date = cert_obj.not_valid_after
                            days_until_expiry = (expiry_date - datetime.datetime.now()).days
                            expiry_str = expiry_date.strftime('%Y-%m-%d %H:%M:%S')
                        except Exception as e:
                            print(f"    Error parsing certificate {name}: {e}")
                            expiry_str = 'Parse error'
                    else:
                        expiry_str = 'No PEM data'
                    
                    certificates.append({
                        'hostname': hostname,
                        'port': 'DB',
                        'service_name': service_name,
                        'certificate_name': name,
                        'subject_cn': subject,
                        'issuer_cn': issuer,
                        'expiry_date': expiry_str,
                        'days_until_expiry': days_until_expiry,
                        'certificate_type': 'CUCM Certificate'
                    })
            
            print(f"  Found {len(certificates)} certificates in CUCM database")
            
        else:
            print(f"  AXL API returned status {response.status_code}")
            if response.status_code == 401:
                print("  Check credentials in credentials.yml")
            elif response.status_code == 503:
                print("  AXL service may not be enabled")
                
    except Exception as e:
        print(f"  AXL API error: {e}")
    
    return certificates

def generate_prometheus_metrics(certificates):
    """Generate Prometheus metrics format"""
    metrics = []
    
    # Collection info
    now = datetime.datetime.now()
    collection_timestamp = int(now.strftime('%Y%m%d'))  # Format: YYYYMMDD
    hostname = certificates[0]['hostname'] if certificates else 'unknown'
    
    # Summary statistics
    total_certs = len(certificates)
    expired_certs = len([c for c in certificates if c['days_until_expiry'] < 0])
    warning_certs = len([c for c in certificates if 0 <= c['days_until_expiry'] < 30])
    critical_certs = len([c for c in certificates if 0 <= c['days_until_expiry'] < 7])
    
    # Add summary metrics
    metrics.append(f'cucm_collection_timestamp{{hostname="{hostname}"}} {collection_timestamp}')
    metrics.append(f'cucm_total_certificates{{hostname="{hostname}"}} {total_certs}')
    metrics.append(f'cucm_expired_certificates{{hostname="{hostname}"}} {expired_certs}')
    metrics.append(f'cucm_warning_certificates{{hostname="{hostname}"}} {warning_certs}')
    metrics.append(f'cucm_critical_certificates{{hostname="{hostname}"}} {critical_certs}')
    
    # Add individual certificate metrics
    for cert in certificates:
        labels = [
            f'service="{cert["service_name"]}"',
            f'hostname="{cert["hostname"]}"',
            f'port="{cert["port"]}"',
            f'certificate_name="{cert["certificate_name"]}"',
            f'subject_cn="{cert["subject_cn"]}"',
            f'issuer_cn="{cert["issuer_cn"]}"',
            f'certificate_type="{cert["certificate_type"]}"'
        ]
        
        metric_line = f'cucm_certificate_expiry_days{{{",".join(labels)}}} {cert["days_until_expiry"]}'
        metrics.append(metric_line)
    
    # Add blank line at end for Prometheus EOF detection
    return "\n".join(metrics) + "\n\n"

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cucm_cert_monitor.py <hostname> [output_file] [output_dir] [--skip-axl]")
        print("Example: python3 cucm_cert_monitor.py 172.16.40.81 cucm_certs.prom ./ --skip-axl")
        sys.exit(1)
    
    hostname = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "cucm_certificates.prom"
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "./"
    
    certificates = []
    
    print(f"Checking certificates on {hostname}...")
    
    # Try AXL API to get database certificates (skip if flag provided)
    if len(sys.argv) <= 4 or sys.argv[4] != '--skip-axl':
        api_certificates = get_certificates_via_axl(hostname)
        certificates.extend(api_certificates)
    
    # Then check web SSL certificates  
    print(f"Checking web SSL certificates...")
    ports_to_check = [8443, 443]
    
    for port in ports_to_check:
        cert_info = get_certificate_via_openssl(hostname, port)
        if cert_info:
            certificates.append(cert_info)
            days = cert_info['days_until_expiry']
            if days < 0:
                status = "EXPIRED"
            elif days < 7:
                status = "CRITICAL"
            elif days < 30:
                status = "WARNING"
            else:
                status = "OK"
            print(f"  Port {port}: {cert_info['certificate_name']} - {days} days ({status})")
        else:
            print(f"  Port {port}: No certificate or connection failed")
    
    if not certificates:
        print("No certificates found!")
        sys.exit(1)
    
    # Generate metrics
    metrics = generate_prometheus_metrics(certificates)
    
    # Save to file
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    full_path = output_path / output_file
    
    with open(full_path, 'w') as f:
        f.write(metrics)
    
    print(f"\nPrometheus metrics saved to {full_path}")
    
    # Summary
    now = datetime.datetime.now()
    collection_date = now.strftime("%Y-%m-%d %H:%M:%S")
    total_certs = len(certificates)
    expired_certs = len([c for c in certificates if c['days_until_expiry'] < 0])
    warning_certs = len([c for c in certificates if 0 <= c['days_until_expiry'] < 30])
    critical_certs = len([c for c in certificates if 0 <= c['days_until_expiry'] < 7])
    
    print(f"\nCollection Date: {collection_date}")
    print(f"Summary: Total={total_certs}, Expired={expired_certs}, Warning={warning_certs}, Critical={critical_certs}")

if __name__ == "__main__":
    main()