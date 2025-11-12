import nmap
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from agent_logger import Logger
import json
import os
class NetworkScanner:
    def __init__(self):
        """Initialize the NetworkScanner with Nmap PortScanner."""
        self.nm = nmap.PortScanner()
        self.logger = Logger().get_logger()

        self.output_dir = os.path.join("Data")
        os.makedirs(self.output_dir, exist_ok=True)
        self.output_file = os.path.join(self.output_dir, "processed_scan.json")


    def scan(self, network_range):
        """Perform an Nmap scan on the specified network range."""
        self.logger.info(f"Starting network scan on {network_range}...")
        try:
            self.nm.scan(hosts=network_range, arguments='-T4 -A -sS')
            self.logger.info("Scan completed.")
            # chnages return scanned hosts dATA
            return self.nm[network_range] 
        # return self.nm[network_range] if network_range in self.nm.all_hosts() else None
 
        except nmap.PortScannerError as e:
            self.logger.error(f"Scan failed: {e}. Try running with sudo.")
            # sys.exit(1)
            return None

    def scan_network(self, network, max_workers=10):
        """Discover active hosts and scan them in parallel using ThreadPoolExecutor."""
        self.nm.scan(hosts=network, arguments='-sn')  # Ping scan to find active hosts
        active_hosts = [host for host in self.nm.all_hosts() if self.nm[host].state() == 'up']
        self.logger.info(f"Found {len(active_hosts)} active hosts.")

        self.scan_results = {}  # Store all scanned host data ip as key

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_host = {
                executor.submit(self.scan, host): host
                for host in active_hosts
            }
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    result=future.result()  # Wait for scan to complete
                    if result:
                        self.scan_results[host] = result
                except Exception as e:
                    self.logger.error(f"Error scanning {host}: {e}")

    def compile_results(self):
        """Compile scan results and perform vulnerability assessment."""
        results = []

        for host, host_data in self.scan_results.items():

            # print(host,",,,,,,," ,host_data)
            
            if host_data['status']['state'] != 'up':
                continue
          
            # print(f"{host}....{json.dumps(host_data, indent=4)}/n")

            host_info = {
                'hostname': host_data['hostnames'][0]['name'] if host_data['hostnames'] else '',
                'ip': host,
                'mac': host_data['addresses'].get('mac', ''),
                'os': {
                    'family': '',
                    'name': '',
                    'version': '',
                    'accuracy': '',
                    'cpe': ''
                },
                'ports': []
            }

             # Process the OS match information 
            if 'osmatch' in host_data and host_data['osmatch']:
                os_match = host_data['osmatch'][0]
                os_classes = os_match.get('osclass', [])

                if os_classes:
                    osclass = os_classes[0]
                    cpe_list = osclass.get('cpe', [])
                    cpe_value = cpe_list[0].replace('/', '2.3:') if cpe_list else ''

                    host_info['os'] = {
                        'family': osclass.get('osfamily', ''),
                        'name': os_match.get('name', ''),
                        'version': osclass.get('osgen', ''),
                        'accuracy': os_match.get('accuracy', ''),
                        'cpe': cpe_value
                    }
                else:
                    host_info['os'] = {
                        'family': '',
                        'name': os_match.get('name', ''),
                        'version': '',
                        'accuracy': os_match.get('accuracy', ''),
                        'cpe': ''
                    }
            proto_used=set()
            for proto_info in host_data.get('portused',[]):
                # proto= tcp,udp 
                proto_used.add(proto_info['proto'])  #tcp,udp if multiple tcp in portused comes
            for proto in proto_used:
                # Check the service information if available
                if proto in host_data:  #tcp/udp key in host_data
                    for port, service in host_data[proto].items():  #{80:data,135:data}
                        port_info = {
                        'port': port,
                        'protocol': proto,
                        'state': service.get('state', ''),
                        'service': service.get('name', ''),
                        'version': service.get('version', ''),

                        'cpe': service.get('cpe', '').replace('/', '2.3:')
                    }
                        host_info['ports'].append(port_info)

            results.append(host_info)
            
        with open(self.output_file, "w") as f:
            json.dump(results, f, indent=4)

        return results

    def run(self, network_range):
        """Run the network scan and compile results, then display them."""
        network_range = str(network_range).strip()
        self.scan_network(network_range)
        results = self.compile_results()
        self.logger.info("Scan completed")

        return results


if __name__ == "__main__":
    network_range = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")
    scanner = NetworkScanner()
    scanner.run(network_range)
    
# print(scanner.run(network_range))
    # with open("Network_Scanner/result.json", "w") as f:
    #     f.write(scanner.run(network_range))