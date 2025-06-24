#!/usr/bin/env python3

import requests
import yaml
import datetime
import sys
import logging
import json
from urllib3.packages.urllib3.exceptions import InsecureRequestWarning
from xml.etree import ElementTree as ET

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class CUCMConfig:
    def __init__(self, config_file='config.yml', credentials_file='credentials.yml'):
        with open(config_file, 'r') as f:
            self.config = yaml.safe_load(f)
        
        with open(credentials_file, 'r') as f:
            self.credentials = yaml.safe_load(f)
    
    def get_cucm_url(self):
        host = self.config['cucm']['host']
        port = self.config['cucm']['port']
        return f"https://{host}:{port}"
    
    def get_api_endpoint(self, api_type=None):
        if not api_type:
            api_type = self.config['api']['preferred_method']
        return self.config['api']['endpoints'][api_type]

class CUCMAPIClient:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.verify = self.config.config['cucm']['verify_ssl']
        self.session.timeout = self.config.config['cucm']['timeout']
        
        self.username = self.config.credentials['ansible_user']
        self.password = self.config.credentials['ansible_password']
        self.base_url = self.config.get_cucm_url()
        
        self.session.auth = (self.username, self.password)
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        self.logger = self._setup_logging()

    def _setup_logging(self):
        logging.basicConfig(
            level=getattr(logging, self.config.config['logging']['level']),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.config['logging']['file']),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)

    def test_connection(self):
        """Test CUCM API connectivity"""
        try:
            response = self.session.get(f"{self.base_url}/ccmadmin/")
            return response.status_code == 200 or response.status_code == 302
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False

    def get_certificates_via_certificate_api(self):
        """Get certificates using Certificate Management API"""
        certificates = []
        endpoint = self.config.get_api_endpoint('certificate_management')
        url = f"{self.base_url}{endpoint}"
        
        try:
            self.logger.info(f"Fetching certificates from Certificate Management API: {url}")
            response = self.session.get(f"{url}list")
            
            if response.status_code == 200:
                data = response.json() if response.content else {}
                # Parse certificate data from response
                for cert_data in data.get('certificates', []):
                    cert_info = self._parse_certificate_data(cert_data)
                    if cert_info:
                        certificates.append(cert_info)
            else:
                self.logger.warning(f"Certificate API returned status {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Certificate Management API failed: {e}")
            
        return certificates

    def get_certificates_via_platform_api(self):
        """Get certificates using Platform Services API"""
        certificates = []
        endpoint = self.config.get_api_endpoint('platform_api')
        url = f"{self.base_url}{endpoint}"
        
        try:
            self.logger.info(f"Fetching certificates from Platform API: {url}")
            response = self.session.get(url)
            
            if response.status_code == 200:
                data = response.json() if response.content else {}
                for service in data.get('services', []):
                    for cert in service.get('certificates', []):
                        cert_info = self._parse_certificate_data(cert, service.get('name'))
                        if cert_info:
                            certificates.append(cert_info)
            else:
                self.logger.warning(f"Platform API returned status {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Platform Services API failed: {e}")
            
        return certificates

    def get_certificates_via_axl(self):
        """Get certificates using AXL SOAP API"""
        certificates = []
        endpoint = self.config.get_api_endpoint('axl')
        url = f"{self.base_url}{endpoint}"
        
        soap_body = """<?xml version="1.0" encoding="UTF-8"?>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" 
                       xmlns:axl="http://www.cisco.com/AXL/API/12.5">
            <soap:Header/>
            <soap:Body>
                <axl:listCertificate>
                    <searchCriteria>
                        <name>%</name>
                    </searchCriteria>
                    <returnedTags>
                        <name/>
                        <certificateType/>
                        <expirationDate/>
                        <subjectName/>
                        <issuerName/>
                    </returnedTags>
                </axl:listCertificate>
            </soap:Body>
        </soap:Envelope>"""
        
        try:
            self.logger.info(f"Fetching certificates from AXL API: {url}")
            self.session.headers.update({
                'Content-Type': 'text/xml; charset=utf-8',
                'SOAPAction': 'CUCM:DB ver=12.5 listCertificate'
            })
            
            response = self.session.post(url, data=soap_body)
            
            if response.status_code == 200:
                root = ET.fromstring(response.content)
                # Parse SOAP response for certificate data
                for cert_elem in root.findall('.//return/certificate'):
                    cert_info = self._parse_axl_certificate(cert_elem)
                    if cert_info:
                        certificates.append(cert_info)
            else:
                self.logger.warning(f"AXL API returned status {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"AXL API failed: {e}")
            
        return certificates

    def _parse_certificate_data(self, cert_data, service_name=None):
        """Parse certificate data from API response"""
        try:
            # Handle different API response formats
            expiry_str = cert_data.get('expirationDate') or cert_data.get('notAfter')
            if not expiry_str:
                return None
                
            # Parse expiry date (handle multiple formats)
            try:
                if 'T' in expiry_str:  # ISO format
                    expiry_date = datetime.datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
                else:  # Standard format
                    expiry_date = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
            except:
                # Try parsing as timestamp
                expiry_date = datetime.datetime.fromtimestamp(int(expiry_str))
            
            days_until_expiry = (expiry_date - datetime.datetime.now()).days
            
            return {
                'service_name': service_name or cert_data.get('service', 'Unknown'),
                'hostname': self.config.config['cucm']['host'],
                'certificate_name': cert_data.get('name', 'Unknown'),
                'subject_cn': cert_data.get('subjectName', 'Unknown'),
                'issuer_cn': cert_data.get('issuerName', 'Unknown'),
                'expiry_date': expiry_str,
                'days_until_expiry': days_until_expiry,
                'certificate_type': cert_data.get('certificateType', 'Unknown')
            }
        except Exception as e:
            self.logger.error(f"Error parsing certificate data: {e}")
            return None

    def _parse_axl_certificate(self, cert_elem):
        """Parse certificate data from AXL SOAP response"""
        try:
            name = cert_elem.find('name').text if cert_elem.find('name') is not None else 'Unknown'
            cert_type = cert_elem.find('certificateType').text if cert_elem.find('certificateType') is not None else 'Unknown'
            expiry = cert_elem.find('expirationDate').text if cert_elem.find('expirationDate') is not None else None
            subject = cert_elem.find('subjectName').text if cert_elem.find('subjectName') is not None else 'Unknown'
            issuer = cert_elem.find('issuerName').text if cert_elem.find('issuerName') is not None else 'Unknown'
            
            if not expiry:
                return None
                
            expiry_date = datetime.datetime.strptime(expiry, '%Y-%m-%d %H:%M:%S.%f')
            days_until_expiry = (expiry_date - datetime.datetime.now()).days
            
            return {
                'service_name': cert_type,
                'hostname': self.config.config['cucm']['host'],
                'certificate_name': name,
                'subject_cn': subject,
                'issuer_cn': issuer,
                'expiry_date': expiry,
                'days_until_expiry': days_until_expiry,
                'certificate_type': cert_type
            }
        except Exception as e:
            self.logger.error(f"Error parsing AXL certificate: {e}")
            return None

    def get_all_certificates(self):
        """Get certificates using the preferred API method with fallbacks"""
        certificates = []
        preferred_method = self.config.config['api']['preferred_method']
        
        self.logger.info(f"Using {preferred_method} as preferred method")
        
        # Try preferred method first
        if preferred_method == 'certificate_management':
            certificates = self.get_certificates_via_certificate_api()
        elif preferred_method == 'platform_api':
            certificates = self.get_certificates_via_platform_api()
        elif preferred_method == 'axl':
            certificates = self.get_certificates_via_axl()
        
        # Fallback to other methods if preferred fails
        if not certificates:
            self.logger.warning(f"Preferred method {preferred_method} failed, trying fallbacks")
            
            if preferred_method != 'certificate_management':
                certificates = self.get_certificates_via_certificate_api()
            
            if not certificates and preferred_method != 'axl':
                certificates = self.get_certificates_via_axl()
        
        return certificates

class PrometheusExporter:
    def __init__(self, config):
        self.config = config
        self.metric_prefix = config.config['prometheus']['metric_prefix']
        
    def generate_metrics(self, certificates):
        """Generate Prometheus metrics"""
        metrics = []
        
        # Add help text for metrics
        metrics.append(f'# HELP {self.metric_prefix}_certificate_expiry_days Days until certificate expiry')
        metrics.append(f'# TYPE {self.metric_prefix}_certificate_expiry_days gauge')
        
        for cert in certificates:
            labels = [
                f'service="{cert["service_name"]}"',
                f'hostname="{cert["hostname"]}"',
                f'certificate_name="{cert["certificate_name"]}"',
                f'subject_cn="{cert["subject_cn"]}"',
                f'issuer_cn="{cert["issuer_cn"]}"',
                f'certificate_type="{cert["certificate_type"]}"'
            ]
            
            metric_line = f'{self.metric_prefix}_certificate_expiry_days{{{",".join(labels)}}} {cert["days_until_expiry"]}'
            metrics.append(metric_line)
        
        # Add summary metrics
        total_certs = len(certificates)
        expired_certs = len([c for c in certificates if c["days_until_expiry"] < 0])
        warning_certs = len([c for c in certificates if 0 <= c["days_until_expiry"] < self.config.config['monitoring']['warning_days']])
        critical_certs = len([c for c in certificates if 0 <= c["days_until_expiry"] < self.config.config['monitoring']['critical_days']])
        
        metrics.append("")
        metrics.append(f'# HELP {self.metric_prefix}_certificates_total Total number of certificates monitored')
        metrics.append(f'# TYPE {self.metric_prefix}_certificates_total gauge')
        metrics.append(f'{self.metric_prefix}_certificates_total{{hostname="{self.config.config["cucm"]["host"]}"}} {total_certs}')
        
        metrics.append("")
        metrics.append(f'# HELP {self.metric_prefix}_certificates_expired Number of expired certificates')
        metrics.append(f'# TYPE {self.metric_prefix}_certificates_expired gauge')
        metrics.append(f'{self.metric_prefix}_certificates_expired{{hostname="{self.config.config["cucm"]["host"]}"}} {expired_certs}')
        
        metrics.append("")
        metrics.append(f'# HELP {self.metric_prefix}_certificates_warning Number of certificates expiring within warning threshold')
        metrics.append(f'# TYPE {self.metric_prefix}_certificates_warning gauge')
        metrics.append(f'{self.metric_prefix}_certificates_warning{{hostname="{self.config.config["cucm"]["host"]}"}} {warning_certs}')
        
        metrics.append("")
        metrics.append(f'# HELP {self.metric_prefix}_certificates_critical Number of certificates expiring within critical threshold')
        metrics.append(f'# TYPE {self.metric_prefix}_certificates_critical gauge')
        metrics.append(f'{self.metric_prefix}_certificates_critical{{hostname="{self.config.config["cucm"]["host"]}"}} {critical_certs}')
        
        # Add collection metadata
        collection_timestamp = int(datetime.datetime.now().timestamp())
        collection_date = datetime.datetime.now().strftime("%Y%m%d")
        
        metrics.append("")
        metrics.append(f'# HELP {self.metric_prefix}_last_collection_timestamp_seconds Unix timestamp of last data collection')
        metrics.append(f'# TYPE {self.metric_prefix}_last_collection_timestamp_seconds gauge')
        metrics.append(f'{self.metric_prefix}_last_collection_timestamp_seconds{{hostname="{self.config.config["cucm"]["host"]}"}} {collection_timestamp}')
        
        metrics.append("")
        metrics.append(f'# HELP {self.metric_prefix}_data_collection_date Data collection date in YYYYMMDD format')
        metrics.append(f'# TYPE {self.metric_prefix}_data_collection_date gauge')
        metrics.append(f'{self.metric_prefix}_data_collection_date{{hostname="{self.config.config["cucm"]["host"]}"}} {collection_date}')
        
        # Add health check metric
        metrics.append("")
        metrics.append(f'# HELP {self.metric_prefix}_collection_success Whether data collection was successful')
        metrics.append(f'# TYPE {self.metric_prefix}_collection_success gauge')
        metrics.append(f'{self.metric_prefix}_collection_success{{hostname="{self.config.config["cucm"]["host"]}"}} 1')
        
        metrics.append("")
        
        return "\n".join(metrics)
    
    def save_metrics(self, certificates, filename=None):
        """Save metrics to file"""
        if not filename:
            filename = self.config.config['monitoring']['output_file']
            
        metrics = self.generate_metrics(certificates)
        
        with open(filename, 'w') as f:
            f.write(metrics)
        
        return filename

def main():
    if len(sys.argv) < 2:
        print("Usage: python cucm_cert_monitor_v2.py [config_file] [credentials_file]")
        print("       python cucm_cert_monitor_v2.py config.yml credentials.yml")
        sys.exit(1)
    
    config_file = sys.argv[1] if len(sys.argv) > 1 else 'config.yml'
    credentials_file = sys.argv[2] if len(sys.argv) > 2 else 'credentials.yml'
    
    try:
        # Load configuration
        config = CUCMConfig(config_file, credentials_file)
        
        # Initialize API client
        client = CUCMAPIClient(config)
        
        # Test connection
        if not client.test_connection():
            print("Failed to connect to CUCM. Check configuration and credentials.")
            sys.exit(1)
        
        # Get certificates
        certificates = client.get_all_certificates()
        
        if not certificates:
            print("No certificates found or API calls failed.")
            sys.exit(1)
        
        # Generate and save Prometheus metrics
        exporter = PrometheusExporter(config)
        output_file = exporter.save_metrics(certificates)
        
        print(f"Prometheus metrics saved to {output_file}")
        print(f"Found {len(certificates)} certificates:")
        
        warning_days = config.config['monitoring']['warning_days']
        critical_days = config.config['monitoring']['critical_days']
        
        for cert in certificates:
            days = cert['days_until_expiry']
            if days < 0:
                status = "EXPIRED"
            elif days < critical_days:
                status = "CRITICAL"
            elif days < warning_days:
                status = "WARNING"
            else:
                status = "OK"
            
            print(f"  {cert['certificate_name']} ({cert['service_name']}): {days} days ({status})")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()