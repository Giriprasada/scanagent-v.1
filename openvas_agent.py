import os
import json
import asyncio
# from lxml import etree
import xml.etree.ElementTree as etree
from datetime import datetime
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from agent_logger import Logger
from typing import List, Dict, Optional, Iterator
import ipaddress
import tenacity
from ping3 import ping
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
import nmap
from dotenv import load_dotenv
import time
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
        self.gmp = None
        self.output_file = os.path.join('Data', 'Openvas_vuln_data.json')
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)

        self.config = {
            'host': os.getenv('OPENVAS_HOST', 'localhost'),  
            'port': int(os.getenv('OPENVAS_PORT', 9390)),  
            'username': os.getenv('OPENVAS_USERNAME', 'admin'),  
            'password': os.getenv('OPENVAS_PASSWORD', 'admin'),  
            'scan_config': 'Full and fast',  
            'port_list_name': 'All IANA assigned TCP and UDP',  
            'max_concurrent_tasks': 10, 
            'batch_size': 1,  
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
    

    # ---------- Connection context manager ----------
    import contextlib
    @contextlib.contextmanager
    def connect(self, retries: int = 3, delay: int = 5) -> Iterator[Gmp]:
        """
        Context manager that yields an authenticated Gmp instance.
        Usage: with self.connect() as gmp:
                   # use gmp
        """
        last_exc = None
        for attempt in range(1, retries + 1):
            try:
                self.logger.info(f"Creating TLSConnection to {self.config['host']}:{self.config['port']} (attempt {attempt})")
                connection = TLSConnection(hostname=self.config['host'], port=self.config['port'])
                # use the same working pattern you said works:
                with Gmp(connection) as gmp:
                    try:
                        gmp.authenticate(self.config['username'], self.config['password'])
                        self.logger.info("Successfully connected to GVM")
                        yield gmp
                        return
                    except Exception as auth_error:
                        self.logger.error(f"Authentication failed: {auth_error}")
                        last_exc = auth_error
                        # raise to outer except to trigger retry logic
                        raise
            except Exception as e:
                self.logger.error(f"Connection attempt {attempt} failed: {e}")
                last_exc = e
                if attempt < retries:
                    time.sleep(delay)
                    self.logger.info("Retrying connection...")
                else:
                    self.logger.critical("All connection attempts failed.")
                    # re-raise final exception so caller knows connect failed
                    raise last_exc
        # If we somehow fall through:
        if last_exc:
            raise last_exc
        raise RuntimeError("connect(): unexpected exit")

    def ensure_connection(self, retries: int = 3, delay: int = 5) -> Gmp:
        """
        Ensure there is a valid, authenticated GMP connection.

        If the existing self.gmp connection is dead or times out,
        this will reconnect automatically and return a new authenticated instance.
        """
        # 1️ If we already have a working connection, check it
        if getattr(self, "gmp", None):
            try:
                # Minimal command to verify connection health
                self.gmp.get_version()
                return self.gmp  # connection is alive
            except Exception as e:
                self.logger.warning(f"GMP connection lost: {e}. Reconnecting...")
                # Clean up old reference
                try:
                    conn = getattr(self.gmp, "connection", None)
                    if conn:
                        conn.close()
                except Exception:
                    pass
                self.gmp = None

        # 2️ Attempt reconnection using the same working connect() method
        last_exc = None
        for attempt in range(1, retries + 1):
            try:
                self.logger.info(f"Reconnecting to GVM ({self.config['host']}:{self.config['port']}) attempt {attempt}/{retries}")
                with self.connect() as gmp:
                    #  copy the live object into self.gmp
                    # note: inside connect(), yield returns an authenticated gmp
                    self.gmp = gmp
                    self.logger.info("Successfully reconnected and authenticated to GVM")
                    return self.gmp
            except Exception as e:
                last_exc = e
                self.logger.error(f"Reconnect attempt {attempt} failed: {e}")
                if attempt < retries:
                    time.sleep(delay)
                else:
                    self.logger.critical("All reconnect attempts failed.")

        # 3️ Raise if all retries exhausted
        if last_exc:
            raise RuntimeError("Failed to ensure GVM connection") from last_exc

        raise RuntimeError("ensure_connection(): unexpected exit")

   # ---------- Scan orchestration ----------
    async def run(self, target: str) -> Dict:
        try:
            if not self.validate_target(target):
                self.logger.error("Invalid target provided")
                return {}

            self.logger.info(f"Scanning {target} for active hosts using nmap")
            active_ips = self.get_active_hosts(target)
            if not active_ips:
                self.logger.error("No active hosts found")
                return {}
            filtered_active_ips = [ip.strip() for ip in active_ips if ip.strip() and ip.strip() not in BLOCKED_HOST_IPS]
            removed_count = len(active_ips) - len(filtered_active_ips)
            if removed_count > 0:
                self.logger.info(f"Removed {removed_count} blocked IP(s) from active host list: {sorted(list(BLOCKED_HOST_IPS))}")

            active_ips = filtered_active_ips
            if not active_ips:
                self.logger.error("No active hosts left to scan after applying blocked IP filter")
                return {}

            batch_size = self.config['batch_size']
            ip_batches = [active_ips[i:i + batch_size] for i in range(0, len(active_ips), batch_size)]
            self.logger.info(f"Scanning {len(active_ips)} active IPs in {len(ip_batches)} batches of {batch_size}")

            # Use the working context-managed connect() here
            try:
                with self.connect() as gmp:
                    # Get configs
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
                        self.logger.error("Scan configuration not found. Trying fallback.")
                        for config_elem in configs_xml.findall('config'):
                            if config_elem.get('id'):
                                config_id = config_elem.get('id')
                                self.logger.info(f"Using fallback config ID: {config_id}")
                                break
                        if not config_id:
                            raise RuntimeError("No scan configurations available")

                    # Get port list
                    port_lists = gmp.get_port_lists()
                    port_lists_xml = etree.fromstring(port_lists)
                    port_list_id = None
                    for pl in port_lists_xml.findall(".//port_list"):
                        name = pl.findtext("name")
                        if name and self.config['port_list_name'] in name:
                            port_list_id = pl.get("id")
                            self.logger.info(f"Located port list: {name} with ID: {port_list_id}")
                            break
                    if not port_list_id:
                        self.logger.error("Port list not found. Trying fallback.")
                        for pl in port_lists_xml.findall(".//port_list"):
                            if pl.get("id"):
                                port_list_id = pl.get("id")
                                self.logger.info(f"Using fallback port list ID: {port_list_id}")
                                break
                        if not port_list_id:
                            raise RuntimeError("No port lists available")

                    # Get scanner
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
                        self.logger.error("Scanner not found. Trying fallback.")
                        for scanner in scanner_xml.findall('.//scanner'):
                            if scanner.get('id'):
                                scanner_id = scanner.get('id')
                                self.logger.info(f"Using fallback scanner ID: {scanner_id}")
                                break
                        if not scanner_id:
                            raise RuntimeError("No scanners available")

                    # Run scans concurrently (respecting semaphore)
                    semaphore = asyncio.Semaphore(self.config['max_concurrent_tasks'])
                    async def limited_scan(ip_batch):
                        async with semaphore:
                            return await self.scan_target_batch(gmp, ip_batch, config_id, scanner_id, port_list_id)

                    tasks = [limited_scan(b) for b in ip_batches]
                    report_ids = await asyncio.gather(*tasks, return_exceptions=True)

                    # process reports (this will attempt to fetch whatever report ids succeeded)
                    network_data = self.process_reports(gmp, report_ids, ip_batches)
                    return network_data

            except Exception as e:
                self.logger.error(f"OpenVAS connection/operation failed: {e}")
                return {}

        except Exception as e:
            self.logger.error(f"Application error during scan: {e}")
            return {}

    # ---------- Task wait & batch scan ----------
    async def wait_for_task(self, gmp: Gmp, task_id: str, check_interval: int = 10) -> bool:
        reconnect_failures = 0
        @tenacity.retry(stop=tenacity.stop_after_attempt(3), wait=tenacity.wait_fixed(5), reraise=True)
        async def get_status_once():
            status = gmp.get_task(task_id)
            status_xml = etree.fromstring(status)
            status_elem = status_xml.find('.//status')
            if status_elem is None:
                raise RuntimeError("Status element not found")
            return status_elem.text

        while True:
            try:
                status = await get_status_once()
                self.logger.info(f"Task {task_id} status: {status}")
                reconnect_failures = 0  # reset on success

                if status.lower() == 'done':
                    return True
                await asyncio.sleep(max(check_interval, 5))
            except Exception as e:
                self.logger.error(f"Error waiting for task {task_id}: {e}")
                # Try a direct reconnect (not context manager here) to recover
                try:
                    self.logger.info("Attempting persistent reconnection via ensure_connection()...")
                    self.gmp = self.ensure_connection()
                    gmp = self.gmp # update local reference
                    reconnect_failures = 0
                    self.logger.info("Reconnected to GVM successfully during wait loop.")
                    await asyncio.sleep(5)
                except Exception as re:
                    reconnect_failures += 1
                    self.logger.error(f"Reconnect attempt failed during wait loop: {re}")
                    if reconnect_failures >= 3:
                        self.logger.critical(
                            f"Maximum reconnection attempts ({3}) reached for task {task_id}. "
                            "Saving state for later resumption and aborting wait loop."
                        )
                    return False
                # --- Safe exponential backoff before retry ---
                backoff = min(max(check_interval, 5) * max(reconnect_failures, 1), 300)
                self.logger.warning(f"Waiting {backoff}s before next reconnect attempt...")
                await asyncio.sleep(backoff)

    async def scan_target_batch(self, gmp: Gmp, target_ips: List[str], config_id: str, scanner_id: str, port_list_id: str) -> Optional[str]:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_name = f'Network_Scan_{timestamp}_{target_ips[0].replace(".", "_")}'
        try:
            self.logger.info(f"Creating scan target {target_name} for IPs: {', '.join(target_ips)}")
            target = gmp.create_target(name=target_name, hosts=target_ips, port_list_id=port_list_id)
            target_xml = etree.fromstring(target)
            target_id = target_xml.get('id')
            if not target_id:
                self.logger.error(f"Failed to create target {target_name}")
                return None

            task = gmp.create_task(name=f'Quick_Vulnerability_Scan_{timestamp}', config_id=config_id, target_id=target_id, scanner_id=scanner_id)
            task_xml = etree.fromstring(task)
            task_id = task_xml.get('id')
            if not task_id:
                self.logger.error("Failed to create task")
                return None

            task_xml = gmp.start_task(task_id)
            task_root = etree.fromstring(task_xml)
            report_id = task_root.findtext('report_id')
            if not report_id:
                self.logger.error(f"Empty report_id for task {task_id}")
                return None

            self.logger.info(f"Task {task_id} started. Report ID: {report_id}")
            await self.wait_for_task(gmp, task_id)
            return report_id

        except Exception as e:
            # try to fetch partial report on failure if possible
            self.logger.error(f"Error running scan for {target_ips}: {e}")
            try:
                # Hardcoded XML format ID (as you requested earlier)
                report_format_id = "a994b278-1f62-11e1-96ac-406186ea4fc5"
                if 'report_id' in locals() and report_id:
                    partial = gmp.get_report(report_id=report_id, report_format_id=report_format_id, details=True, ignore_pagination=True)
                    parsed = self.parse_xml_report(partial, target_ips)
                    if parsed:
                        with open(self.output_file, 'w', encoding='utf-8') as f:
                            json.dump(parsed, f, indent=4)
                        self.logger.info("Saved partial report after failure.")
                        return report_id
            except Exception as fetch_error:
                self.logger.error(f"Failed to fetch partial report: {fetch_error}")
            return None

    def process_reports(self, gmp: Gmp, report_ids: List[Optional[str]], target_ip_batches: List[List[str]]) -> Dict:
        report_format_id = "a994b278-1f62-11e1-96ac-406186ea4fc5"
        network_data = {}
        for report_id, ip_batch in zip(report_ids, target_ip_batches):
            if isinstance(report_id, Exception):
                self.logger.error(f"Skipping report for IPs {ip_batch}: Exception occurred - {report_id}")
                continue
            if not report_id:
                self.logger.error(f"Skipping report for IPs {ip_batch}: No valid report ID")
                continue
            try:
                self.logger.info(f"Fetching report {report_id}")
                report = gmp.get_report(report_id=report_id, report_format_id=report_format_id, details=True, ignore_pagination=True)
                parsed_data = self.parse_xml_report(report, ip_batch)
                if parsed_data:
                    network_data['scan_info'] = parsed_data.get('scan_info', {})
                    for ip, host_data in parsed_data.get('hosts', {}).items():
                        network_data[ip] = host_data
            except Exception as e:
                self.logger.error(f"Error processing report {report_id}: {e}")

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
                    'total_misconfiguration': 0,
                    'open_ports': {'tcp': [], 'udp': []},
                    'vulnerabilities': [],
                    'misconfigurations':[],
                    'log_risk_factor':[]
                 
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
                        # 'references': [],
                        
                    }

                    refs = nvt.find('refs')
                    if refs is not None:
                        for ref in refs.findall('ref'):
                            ref_type = ref.get('type', '')
                            ref_id = ref.get('id', '')
                            if ref_type == 'cve':
                                vuln_data['cves'].append(ref_id)

                            # vuln_data['references'].append({'type': ref_type, 'id': ref_id})

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

                    risk_factor = vuln_data.get("impact", {}).get("risk_factor")
                    if risk_factor and risk_factor.lower() == 'log':
                        parsed_data['hosts'][host]['log_risk_factor'].append(vuln_data)
                    else:
                        if not vuln_data['cves']:
                                parsed_data['hosts'][host]['misconfigurations'].append(vuln_data)
                                parsed_data['hosts'][host]['total_misconfiguration'] += 1
                        else:
                        
                                parsed_data['hosts'][host]['vulnerabilities'].append(vuln_data)
                                parsed_data['hosts'][host]['total_vulnerabilities'] += 1
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
