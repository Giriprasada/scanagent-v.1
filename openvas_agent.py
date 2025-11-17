import os
import json
import asyncio
# from lxml import etree
import xml.etree.ElementTree as etree
from datetime import datetime
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from agent_logger import Logger
from typing import List, Dict, Optional
import ipaddress
import tenacity
from ping3 import ping
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
import nmap
from dotenv import load_dotenv

# Hardcoded list of IPs to avoid during scanning
BLOCKED_HOST_IPS = {
    "192.168.40.1",
    "172.16.16.16",
    "192.168.30.1",
    "192.168.30.9",
    "172.16.16.17",
    "192.168.40.8",
    "192.168.10.6",
    "192.168.10.9",
    "192.168.10.11"
}

class OpenVASScanner:
    """A class to manage OpenVAS vulnerability scanning operations, including target validation, host discovery, and report processing."""

    def __init__(self):
        """Initialize the scanner by loading configuration from a .env file and setting up the logger."""
        load_dotenv()  
        self.logger = Logger().get_logger()  
        
        self.output_file = os.path.join('Data', 'Openvas_vuln_data.json')
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)

        self.config = {
            'host': os.getenv('OPENVAS_HOST', '192.168.10.11'),  
            'port': int(os.getenv('OPENVAS_PORT', 9390)),  
            'username': os.getenv('OPENVAS_USERNAME', 'admin'),  
            'password': os.getenv('OPENVAS_PASSWORD', 'admin'),  
            'scan_config': 'Full and fast',  
            'port_list_name': 'All IANA assigned TCP and UDP',  
            'max_concurrent_tasks': 10, 
            'batch_size': 5,  
            'ping_timeout': 2.0  
        }

    def validate_target(self, target: str) -> bool:
        """Validate whether the provided target is a single IP address or a valid CIDR range.

        Args:
            target (str): IP address (e.g., '192.168.1.1') or CIDR range (e.g., '192.168.1.0/24')

        Returns:
            bool: True if valid, False otherwise
        """
        try:
            ipaddress.ip_address(target)  # Check if target is a single IP
            self.logger.info(f"Validated single IP address: {target}")
            return True
        except ValueError:
            try:
                ipaddress.ip_network(target, strict=False)  # Check if target is a CIDR range
                self.logger.info(f"Validated CIDR range: {target}")
                return True
            except ValueError as e:
                self.logger.error(f"Invalid target {target}: {e}")
                return False

    def expand_subnet(self, target: str) -> List[str]:
        """Expand a single IP or CIDR range into a list of individual IP addresses.

        Args:
            target (str): IP address or CIDR range to expand

        Returns:
            List[str]: List of IP addresses as strings
        """
        try:
            ip = ipaddress.ip_address(target)  # Check if target is a single IP
            self.logger.info(f"Processing single IP: {target}")
            return [str(ip)]
        except ValueError:
            try:
                network = ipaddress.ip_network(target, strict=False)  # Expand CIDR range
                self.logger.info(f"Expanding CIDR range: {target}")
                return [str(ip) for ip in network.hosts()]
            except ValueError as e:
                self.logger.error(f"Invalid input {target}: {e}")
                return []

    def get_active_hosts(self, target: str) -> List[str]:
        """Perform an nmap ping scan to identify active hosts in the target range.

        Args:
            target (str): IP address or CIDR range to scan

        Returns:
            List[str]: Sorted list of active host IP addresses
        """
        active_hosts = []
        try:
            nm = nmap.PortScanner()  # Initialize nmap scanner
            self.logger.info(f"Initiating nmap ping scan on: {target}")
            nm.scan(hosts=target, arguments=f'-sn -T4 --host-timeout {int(self.config["ping_timeout"] * 1000)}ms')
            
            for host in nm.all_hosts():
                if nm[host]['status']['state'] == 'up':  # Check if host is active
                    active_hosts.append(host)
                    self.logger.debug(f"Host {host} is active")
                else:
                    self.logger.debug(f"Host {host} is inactive")
            
            self.logger.info(f"Discovered {len(active_hosts)} active hosts")
            return sorted(active_hosts)
        
        except Exception as e:
            self.logger.error(f"Error during nmap scan: {e}")
            return []
    

    def connect(self, retries=3, delay=5):
        """Create a new GVM connection and authenticate."""
        for attempt in range(1, retries + 1):
            try:
                connection = TLSConnection(
                    hostname=self.config['host'],
                    port=self.config['port']
                )
                gmp = Gmp(connection)
                gmp.authenticate(self.config['username'], self.config['password'])
                self.logger.info("Successfully connected to GVM")
                self.gmp = gmp
                return gmp
            except Exception as e:
                self.logger.error(f"GVM connection attempt {attempt} failed: {e}")
                if attempt < retries:
                    time.sleep(delay)
                else:
                    raise

    def ensure_connection(self):
        """Reconnect if connection is lost."""
        if self.gmp is None:
            return self.connect()

        try:
            self.gmp.get_version()
            return self.gmp
        except Exception:
            self.logger.warning("Lost connection to GVM, reconnecting...")
            return self.connect()
        

    async def run(self, target: str) -> Dict:
        """Execute an OpenVAS scan on the specified target, processing active hosts and generating a report.

        Args:
            target (str): IP address or CIDR range to scan

        Returns:
            Dict: Scan results containing host details and vulnerability summary
        """
        try:
            if not self.validate_target(target):  # Validate input target
                self.logger.error("Invalid target provided")
                return {}

            self.logger.info(f"Scanning {target} for active hosts using nmap")
            active_ips = self.get_active_hosts(target)
            if not active_ips:
                self.logger.error("No active hosts found")
                return {}

            # Remove any blocked/ignored IPs from the active list--------------------------HARDCODING
            filtered_active_ips = [ip.strip() for ip in active_ips if ip.strip() and ip.strip() not in BLOCKED_HOST_IPS]
            removed_count = len(active_ips) - len(filtered_active_ips)
            if removed_count > 0:
                self.logger.info(f"Removed {removed_count} blocked IP(s) from active host list: {sorted(list(BLOCKED_HOST_IPS))}")

            active_ips = filtered_active_ips
            if not active_ips:
                self.logger.error("No active hosts left to scan after applying blocked IP filter")
                return {}
# --------------------------HARDCODING-----------------------------------------------------
            
            batch_size = self.config['batch_size']
            ip_batches = [active_ips[i:i + batch_size] for i in range(0, len(active_ips), batch_size)]
            self.logger.info(f"Scanning {len(active_ips)} active IPs in {len(ip_batches)} batches of {batch_size}")

            try:
                connection = TLSConnection(hostname=self.config['host'], port=self.config['port'])
                
                with Gmp(connection) as gmp:
                    try:
                        gmp.authenticate(self.config['username'], self.config['password'])  # Authenticate with OpenVAS
                        self.logger.info("Successfully connected to GVM")
                    except Exception as auth_error:
                        self.logger.error(f"Authentication failed: {auth_error}")
                        self.logger.error("Please check your OpenVAS credentials in .env file")
                        return {}

                    # Retrieve scan configuration ID
                    try:
                        configs_raw = gmp.get_scan_configs()
                        configs_xml = etree.fromstring(configs_raw)
                        config_id = None
                        scan_config_name = self.config['scan_config']
                        for config_elem in configs_xml.findall('config'):
                            name = config_elem.findtext('name')
                            if name and scan_config_name in name:
                                config_id = config_elem.get('id')
                                self.logger.info(f"Located scan config '{name}' with ID: {config_id}")
                                break
                        if not config_id:
                            self.logger.error("Scan configuration not found. Using default config.")
                            # Try to get any available config
                            for config_elem in configs_xml.findall('config'):
                                config_id = config_elem.get('id')
                                if config_id:
                                    self.logger.info(f"Using fallback config with ID: {config_id}")
                                    break
                            if not config_id:
                                raise Exception("No scan configurations available.")
                    except Exception as config_error:
                        self.logger.error(f"Error retrieving scan configurations: {config_error}")
                        return {}

                    # Retrieve port list ID
                    try:
                        port_lists = gmp.get_port_lists()
                        port_lists_xml = etree.fromstring(port_lists)
                        port_list_id = None
                        for pl in port_lists_xml.findall(".//port_list"):
                            name = pl.findtext("name")
                            if self.config['port_list_name'] in name:
                                port_list_id = pl.get("id")
                                self.logger.info(f"Located port list: {name} with ID: {port_list_id}")
                                break
                        if not port_list_id:
                            self.logger.error("Port list not found. Using default port list.")
                            # Try to get any available port list
                            for pl in port_lists_xml.findall(".//port_list"):
                                port_list_id = pl.get("id")
                                if port_list_id:
                                    self.logger.info(f"Using fallback port list with ID: {port_list_id}")
                                    break
                            if not port_list_id:
                                raise Exception("No port lists available.")
                    except Exception as port_error:
                        self.logger.error(f"Error retrieving port lists: {port_error}")
                        return {}

                    # Retrieve scanner ID
                    try:
                        scanners = gmp.get_scanners()
                        scanner_xml = etree.fromstring(scanners)
                        scanner_id = None
                        for scanner in scanner_xml.findall('.//scanner'):
                            name = scanner.findtext('name')
                            if name and 'OpenVAS' in name:
                                scanner_id = scanner.get('id')
                                self.logger.info(f"Located scanner '{name}' with ID: {scanner_id}")
                                break
                        if not scanner_id:
                            self.logger.error("Could not find OpenVAS scanner. Using default scanner.")
                            # Try to get any available scanner
                            for scanner in scanner_xml.findall('.//scanner'):
                                scanner_id = scanner.get('id')
                                if scanner_id:
                                    self.logger.info(f"Using fallback scanner with ID: {scanner_id}")
                                    break
                            if not scanner_id:
                                raise ValueError("No scanners available.")
                    except Exception as scanner_error:
                        self.logger.error(f"Error retrieving scanners: {scanner_error}")
                        return {}

                    # Run scans concurrently with rate limiting
                    semaphore = asyncio.Semaphore(self.config['max_concurrent_tasks'])
                    async def limited_scan(ip_batch):
                        async with semaphore:
                            return await self.scan_target_batch(gmp, ip_batch, config_id, scanner_id, port_list_id)

                    tasks = [limited_scan(ip_batch) for ip_batch in ip_batches]
                    report_ids = await asyncio.gather(*tasks, return_exceptions=True)
                    network_data = self.process_reports(gmp, report_ids, ip_batches)
                    return network_data

            except ConnectionRefusedError:
                self.logger.error(f"Connection refused to OpenVAS at {self.config['host']}:{self.config['port']}")
                self.logger.error("Please ensure OpenVAS is running and accessible")
                self.logger.error("You can start OpenVAS with: sudo systemctl start openvas-scanner")
                return {}
            except Exception as conn_error:
                self.logger.error(f"Connection error: {conn_error}")
                self.logger.error("Please check your OpenVAS configuration and network connectivity")
                return {}

        except Exception as e:
            self.logger.error(f"Application error during scan: {e}")
            return {}

    async def wait_for_task(self, gmp: Gmp, task_id: str, check_interval: int = 10) -> bool:
        """Asynchronously wait for an OpenVAS task to complete, with retry logic.

        Args:
            gmp (Gmp): GMP protocol instance
            task_id (str): ID of the task to monitor
            check_interval (int): Seconds between status checks (default: 10)

        Returns:
            bool: True if task completes successfully
        """
        @tenacity.retry(
            stop=tenacity.stop_after_attempt(3),  # Retry up to 3 times
            wait=tenacity.wait_fixed(5),  # Wait 5 seconds between retries
            retry=tenacity.retry_if_exception_type(Exception),
            reraise=True
        )
        async def check_task():
            try:
                status = gmp.get_task(task_id)  # Fetch task status
                status_xml = etree.fromstring(status)
                status_elem = status_xml.find('.//status')
                if status_elem is None:
                    raise Exception("Status element not found in task response")
                return status_elem.text
            except Exception as e:
                self.logger.error(f"Error fetching task status: {e}")
                # If the connection is lost, reconnect and retry once
                try:
                    self.logger.info("Reconnecting to GMP...")
                    self.gmp = self.ensure_connection()  # <-- implement reconnect here
                    status = self.gmp.get_task(task_id)
                    status_xml = etree.fromstring(status)
                    status_elem = status_xml.find('.//status')
                    return status_elem.text
                except Exception as retry_error:
                    self.logger.error(f"Retry failed: {retry_error}")
                    raise

        while True:
            try:
                status = await check_task()
                self.logger.info(f"Task {task_id} status: {status}")
                if status == 'Done':
                    self.logger.info(f"Task {task_id} completed successfully")
                    return True
                await asyncio.sleep(check_interval)
            except Exception as e:
                self.logger.error(f"Error checking task {task_id} status: {e}")
                await asyncio.sleep(check_interval)

    async def scan_target_batch(self, gmp: Gmp, target_ips: List[str], config_id: str, scanner_id: str, port_list_id: str) -> Optional[str]:
        """Create and execute an OpenVAS scan task for a batch of IP addresses.

        Args:
            gmp (Gmp): GMP protocol instance
            target_ips (List[str]): List of IP addresses to scan
            config_id (str): Scan configuration ID
            scanner_id (str): Scanner ID
            port_list_id (str): Port list ID

        Returns:
            Optional[str]: Report ID if successful, None otherwise
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_name = f'Network_Scan_{timestamp}_{target_ips[0].replace(".", "_")}'
        
        try:
            self.logger.info(f"Creating scan target {target_name} for IPs: {', '.join(target_ips)}")
            
            try:
                target = gmp.create_target(name=target_name, hosts=target_ips, port_list_id=port_list_id)
                target_xml = etree.fromstring(target)
                target_id = target_xml.get('id')
                if not target_id:
                    self.logger.error(f"Failed to create target {target_name}")
                    return None
                self.logger.info(f"Created target {target_name} with ID: {target_id}")
            except Exception as target_error:
                self.logger.error(f"Error creating target {target_name}: {target_error}")
                return None

            try:
                task = gmp.create_task(
                    name=f'Quick_Vulnerability_Scan_{timestamp}',
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id=scanner_id
                )
                task_xml = etree.fromstring(task)
                task_id = task_xml.get('id')
                if not task_id:
                    self.logger.error(f"Failed to create task for target {target_id}")
                    return None
                self.logger.info(f"Created task with ID: {task_id}")
            except Exception as task_error:
                self.logger.error(f"Error creating task: {task_error}")
                return None

            try:
                task_xml = gmp.start_task(task_id)
                task_root = etree.fromstring(task_xml)
                report_id_elem = task_root.find('report_id')
                if report_id_elem is None:
                    self.logger.error(f"Failed to extract report ID for task {task_id}")
                    return None
                report_id = report_id_elem.text
                if not report_id:
                    self.logger.error(f"Empty report ID for task {task_id}")
                    return None
                self.logger.info(f"Task {task_id} started. Report ID: {report_id}")
            except Exception as start_error:
                self.logger.error(f"Error starting task {task_id}: {start_error}")
                return None

            try:
                await self.wait_for_task(gmp, task_id)
                return report_id
            except Exception as wait_error:
                self.logger.error(f"Error waiting for task {task_id}: {wait_error}")
                return None

        except Exception as e:
            self.logger.error(f"Error processing target batch {target_ips}: {e}")
            return None

    def process_reports(self, gmp: Gmp, report_ids: List[Optional[str]], target_ip_batches: List[List[str]]) -> Dict:
        """Process scan reports and consolidate results into a JSON file.

        Args:
            gmp (Gmp): GMP protocol instance
            report_ids (List[Optional[str]]): List of report IDs
            target_ip_batches (List[List[str]]): List of IP address batches

        Returns:
            Dict: Consolidated scan results
        """
        report_format_id = "a994b278-1f62-11e1-96ac-406186ea4fc5"  # XML report format ID
        network_data = {
            'summary': {
                'total_vulnerabilities': 0,
                'by_severity': {'High': 0, 'Medium': 0, 'Low': 0, 'Log': 0},
                'by_port': {},
                'total_cves': set()
            }
        }
        
        for report_id, ip_batch in zip(report_ids, target_ip_batches):
            if isinstance(report_id, Exception):
                self.logger.error(f"Skipping report for IPs {ip_batch}: Exception occurred - {report_id}")
                continue
            
            if not report_id:
                self.logger.error(f"Skipping report for IPs {ip_batch}: No valid report ID")
                continue
                
            print(f"Processing report {report_id} for IPs: {ip_batch}")

            try:
                self.logger.info(f"Fetching report {report_id}")
                report = gmp.get_report(
                    report_id=report_id,
                    report_format_id=report_format_id,
                    details=True,
                    ignore_pagination=True
                )
                parsed_data = self.parse_xml_report(report, ip_batch)
                if parsed_data:
                    for ip, host_data in parsed_data['hosts'].items():
                        network_data[ip] = host_data
                    network_data['summary']['total_vulnerabilities'] += parsed_data['summary']['total_vulnerabilities']
                    for severity, count in parsed_data['summary']['by_severity'].items():
                        network_data['summary']['by_severity'][severity] += count
                    for port, count in parsed_data['summary']['by_port'].items():
                        network_data['summary']['by_port'][port] = network_data['summary']['by_port'].get(port, 0) + count
                    network_data['summary']['total_cves'].update(parsed_data['summary']['total_cves'])

            except Exception as e:
                self.logger.error(f"Error processing report {report_id}: {e}")

        network_data['summary']['total_cves'] = sorted(list(network_data['summary']['total_cves']))
        
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(network_data, f, indent=4)
            self.logger.info(f"Saved vulnerability report to {self.output_file}")
        except Exception as e:
            self.logger.error(f"Error saving {self.output_file}: {e}")

        return network_data

    def parse_xml_report(self, xml_content: str, target_ips: List[str]) -> Optional[Dict]:
        """Parse an OpenVAS XML report, extracting details for specified IPs.

        Args:
            xml_content (str): XML content of the report
            target_ips (List[str]): List of target IP addresses

        Returns:
            Optional[Dict]: Parsed report data or None if parsing fails
        """
        try:
            parsed_data = {
                'scan_info': {},
                'hosts': {},
                'summary': {
                    'total_vulnerabilities': 0,
                    'by_severity': {'High': 0, 'Medium': 0, 'Low': 0, 'Log': 0},
                    'by_port': {},
                    'total_cves': set()
                }
            }
            
            try:
                root = etree.fromstring(xml_content.encode('utf-8'))  # Parse XML content
            except etree.XMLSyntaxError as e:
                self.logger.error(f"Failed to parse XML: {e}")
                return None
            
            report = root.find('.//report')
            if report is None:
                self.logger.error("No report element found in XML")
                return None
                
            # print(f"[*] Parsing XML report for IPs: {target_ips}")
            
            # Extract scan metadata
            parsed_data['scan_info'] = {
                'scan_start': report.findtext('.//scan_start', 'N/A'),
                'scan_end': report.findtext('.//scan_end', 'N/A'),
                'total_hosts': len(target_ips),
                'scan_status': report.findtext('.//scan_run_status', 'N/A'),
                'task_name': report.findtext('.//task/name', 'N/A'),
                'overall_severity': report.findtext('.//severity', '0.0')
            }

            # Process host information
            for host in report.findall('.//host'):
                ip = host.findtext('ip', '').strip()
                if ip not in target_ips:
                    continue
                # print(f"[*] Processing host IP: {ip}")

                host_info = {
                    'ip_address': ip,
                    'hostname': None,
                    'mac_address': None,
                    'operating_system': None,
                    'cpe': None,
                    'total_vulnerabilities': 0,
                    'open_ports': {'tcp': [], 'udp': []},
                    'vulnerabilities': {'High': [], 'Medium': [], 'Low': [], 'Log': []},
                    'services': {}
                }

                for detail in host.findall('.//detail'):
                    name = detail.findtext('name', '').strip().lower()
                    value = detail.findtext('value', '').strip()
                    if not value or value.lower() in ['unknown', '0', 'n/a']:
                        continue
                        
                    if name == 'mac':
                        host_info['mac_address'] = value
                    elif name == 'os':
                        host_info['cpe'] = value
                    elif name == 'best_os_txt':
                        host_info['operating_system'] = value
                    elif name == 'hostname':
                        host_info['hostname'] = value
                    elif name == 'tcp_ports':
                        try:
                            host_info['open_ports']['tcp'] = [int(p.strip()) for p in value.split(',') if p.strip().isdigit()]
                        except ValueError:
                            self.logger.warning(f"Failed to parse TCP ports: {value}")
                    elif name == 'udp_ports':
                        try:
                            host_info['open_ports']['udp'] = [int(p.strip()) for p in value.split(',') if p.strip().isdigit()]
                        except ValueError:
                            self.logger.warning(f"Failed to parse UDP ports: {value}")

                if ip not in parsed_data['hosts']:
                    parsed_data['hosts'][ip] = host_info
                else:
                    existing = parsed_data['hosts'][ip]
                    for key in ['mac_address', 'hostname', 'operating_system', 'cpe']:
                        if not existing[key] and host_info[key]:
                            existing[key] = host_info[key]
                    existing['open_ports']['tcp'].extend(host_info['open_ports']['tcp'])
                    existing['open_ports']['udp'].extend(host_info['open_ports']['udp'])
                    existing['open_ports']['tcp'] = list(set(existing['open_ports']['tcp']))
                    existing['open_ports']['udp'] = list(set(existing['open_ports']['udp']))

            # Process vulnerability results
            for result in report.findall('.//results/result'):
                host = result.findtext('host', 'N/A')
                if host not in parsed_data['hosts']:
                    continue

                port = result.findtext('port', 'N/A')
                threat = result.findtext('threat', 'N/A')
                
                try:
                    severity = float(result.findtext('severity', '0.0'))
                except (ValueError, TypeError):
                    severity = 0.0
                    
                qod = result.findtext('.//qod/value', 'N/A')

                nvt = result.find('nvt')
                if nvt is not None:
                    vuln_data = {
                        'name': nvt.findtext('name', 'Unknown').strip(),
                        'summary': result.findtext('description', 'N/A'),
                        'vulnerability_insight': '',
                        'affected_software': [],
                        'impact': {
                            'cvss_base_score': nvt.findtext('cvss_base', '0.0'),
                            'cvss_vector': nvt.findtext('cvss_base_vector', 'N/A'),
                            'risk_factor': threat,
                            'severity_score': severity
                        },
                        'solution': {
                            'description': 'N/A',
                            'type': 'N/A',
                            'effort': 'N/A'
                        },
                        'detection': {
                            'method': nvt.findtext('family', 'N/A'),
                            'quality': qod,
                            'details': result.findtext('notes', 'N/A')
                        },
                        'port_protocol': port,
                        'cves': [],
                        'references': [],
                        'timestamps': {
                            'detected': result.findtext('detection_time', 'N/A'),
                            'creation': nvt.findtext('creation_time', 'N/A'),
                            'modification': nvt.findtext('modification_time', 'N/A')
                        }
                    }

                    refs = nvt.find('refs')
                    if refs is not None:
                        for ref in refs.findall('ref'):
                            ref_type = ref.get('type', '')
                            ref_id = ref.get('id', '')
                            if ref_type == 'cve':
                                vuln_data['cves'].append(ref_id)
                                parsed_data['summary']['total_cves'].add(ref_id)
                            vuln_data['references'].append({'type': ref_type, 'id': ref_id})

                    tags = nvt.findtext('tags', '')
                    if tags:
                        try:
                            tag_dict = {}
                            for item in tags.split('|'):
                                if '=' in item:
                                    k, v = item.split('=', 1)
                                    tag_dict[k.strip()] = v.strip()
                            
                            vuln_data['vulnerability_insight'] = tag_dict.get('insight', '')
                            vuln_data['affected_software'] = [s.strip() for s in tag_dict.get('affected', '').split(',') if s.strip()]
                            vuln_data['solution']['description'] = tag_dict.get('solution', 'N/A')
                            vuln_data['solution']['type'] = tag_dict.get('solution_type', 'N/A')
                            vuln_data['solution']['effort'] = tag_dict.get('solution_effort', 'N/A')
                        except Exception as e:
                            self.logger.warning(f"Failed to parse tags: {e}")

                    if threat in parsed_data['hosts'][host]['vulnerabilities']:
                        parsed_data['hosts'][host]['vulnerabilities'][threat].append(vuln_data)
                        parsed_data['hosts'][host]['total_vulnerabilities'] += 1
                        parsed_data['summary']['total_vulnerabilities'] += 1
                        parsed_data['summary']['by_severity'][threat] += 1
                        if port != 'N/A':
                            parsed_data['summary']['by_port'][port] = parsed_data['summary']['by_port'].get(port, 0) + 1

            parsed_data['summary']['total_cves'] = sorted(list(parsed_data['summary']['total_cves']))
            for host_data in parsed_data['hosts'].values():
                host_data['open_ports']['tcp'] = sorted(host_data['open_ports']['tcp'])
                host_data['open_ports']['udp'] = sorted(host_data['open_ports']['udp'])
            
            return parsed_data

        except Exception as e:
            self.logger.error(f"Error parsing XML report: {e}")
            return None

if __name__ == '__main__':
    import time
    try:
        scanner = OpenVASScanner()  # Create scanner instance
        start_time = time.time()
        target = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")  # Prompt for target input
        
        if not target.strip():
            print("No target provided. Exiting.")
            exit(1)
            
        result = asyncio.run(scanner.run(target))  # Execute scan
        
        if result:
            print(f"Scan completed successfully!")
            print(f"Results saved to: {scanner.output_file}")
        else:
            print("Scan failed or no results obtained.")
            
        print(f"Time taken: {time.time() - start_time:.2f} seconds")  # Display execution time
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"Unexpected error: {e}")
        print("Please check your configuration and try again.")