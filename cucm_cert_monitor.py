#!/usr/bin/env python3

import requests
import yaml
import ssl
import socket
import datetime
import sys
from urllib3.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class CUCMCertificateMonitor:
    def __init__(self, cucm_host, credentials_file='credentials.yml'):
        self.cucm_host = cucm_host
        self.base_url = f"https://{cucm_host}:8443"
        self.session = requests.Session()
        self.session.verify = False
        
        with open(credentials_file, 'r') as f:
            creds = yaml.safe_load(f)
            self.username = creds['ansible_user']
            self.password = creds['ansible_password']
        
        self.session.auth = (self.username, self.password)
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

    def get_certificate_expiry_days(self, hostname, port=443):
        """Get certificate expiry days for a given host/port"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
            not_after = cert['notAfter']
            expiry_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (expiry_date - datetime.datetime.now()).days
            
            return {
                'subject': dict(x[0] for x in cert['subject']),
                'issuer': dict(x[0] for x in cert['issuer']),
                'not_after': not_after,
                'days_until_expiry': days_until_expiry
            }
        except Exception as e:
            print(f"Error getting certificate for {hostname}:{port} - {e}")
            return None

    def get_cucm_services(self):
        """Get CUCM services and their certificate info"""
        services_url = f"{self.base_url}/ccmadmin/controlcenter/ControlCenterServices.do"
        
        services = [
            {'name': 'CUCM Web Interface', 'port': 8443},
            {'name': 'CUCM Admin', 'port': 8443},
            {'name': 'CUCM User Pages', 'port': 8080},
            {'name': 'CUCM HTTPS', 'port': 443},
            {'name': 'CUCM CAPF', 'port': 3804},
            {'name': 'CUCM CTI', 'port': 2748},
            {'name': 'CUCM RIS', 'port': 8001}
        ]
        
        return services

    def get_all_certificates(self):
        """Get all certificate information from CUCM"""
        certificates = []
        
        services = self.get_cucm_services()
        
        for service in services:
            cert_info = self.get_certificate_expiry_days(self.cucm_host, service['port'])
            if cert_info:
                certificates.append({
                    'service_name': service['name'],
                    'hostname': self.cucm_host,
                    'port': service['port'],
                    'subject_cn': cert_info['subject'].get('commonName', 'Unknown'),
                    'issuer_cn': cert_info['issuer'].get('commonName', 'Unknown'),
                    'expiry_date': cert_info['not_after'],
                    'days_until_expiry': cert_info['days_until_expiry']
                })
        
        return certificates

    def generate_prometheus_metrics(self, certificates):
        """Generate Prometheus metrics format"""
        metrics = []
        
        for cert in certificates:
            labels = [
                f'service="{cert["service_name"]}"',
                f'hostname="{cert["hostname"]}"',
                f'port="{cert["port"]}"',
                f'subject_cn="{cert["subject_cn"]}"',
                f'issuer_cn="{cert["issuer_cn"]}"'
            ]
            
            metric_line = f'cucm_certificate_expiry_days{{{",".join(labels)}}} {cert["days_until_expiry"]}'
            metrics.append(metric_line)
        
        collection_date = datetime.datetime.now().strftime("%m%d%Y")
        metrics.append(f'cucm_data_collection_date{{hostname="{self.cucm_host}"}} {collection_date}')
        metrics.append("")
        
        return "\n".join(metrics)

    def save_prometheus_file(self, filename='cucm_certificates.prom'):
        """Save certificate metrics to Prometheus file"""
        certificates = self.get_all_certificates()
        metrics = self.generate_prometheus_metrics(certificates)
        
        with open(filename, 'w') as f:
            f.write(metrics)
        
        print(f"Prometheus metrics saved to {filename}")
        return certificates

def main():
    if len(sys.argv) != 2:
        print("Usage: python cucm_cert_monitor.py <CUCM_HOST>")
        sys.exit(1)
    
    cucm_host = sys.argv[1]
    
    monitor = CUCMCertificateMonitor(cucm_host)
    certificates = monitor.save_prometheus_file()
    
    print(f"\nFound {len(certificates)} certificates:")
    for cert in certificates:
        status = "EXPIRED" if cert['days_until_expiry'] < 0 else "OK"
        if cert['days_until_expiry'] < 30:
            status = "WARNING"
        
        print(f"  {cert['service_name']}: {cert['days_until_expiry']} days ({status})")

if __name__ == "__main__":
    main()