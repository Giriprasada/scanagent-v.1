import socket
import psutil
import ipaddress
import threading
import time
from flask import Flask, request, jsonify
from nmapAgent import NetworkScanner
from openvas_agent import OpenVASScanner
from agent_logger import Logger
from typing import Dict, Optional


class ScanAgent:
    """
    Centralized scan agent that handles triggers from centralized server.
    Supports both Nmap and OpenVAS scanning with auto-detection of primary interface CIDRs.
    """

    def __init__(self):
        self.logger = Logger().get_logger()
        # self.server_host = server_host
        # self.server_port = server_port
        self.agent_ip = None  # Will be set from server payload

        self.nmap_scanner = NetworkScanner()
        self.openvas_scanner = OpenVASScanner()

        self.app = Flask(__name__)
        self.setup_routes()

        self.logger.info("ScanAgent initialized")

    def setup_routes(self):
        """Setup Flask routes for receiving scan triggers."""

        @self.app.route('/trigger_scan', methods=['POST'])
        def trigger_scan():
            try:
                data = request.get_json()
                if not data:
                    return jsonify({"error": "No data provided"}), 400

                scan_type = data.get('scan_type', '').lower() # Data from Server
                ip_range = data.get('ip_range', '').strip() # Data from Server
                server_url  = data.get('central_server_url', '').strip()
                self.agent_ip=data.get('agent_ip', '').strip()
                process_mode = 'auto' if not ip_range else 'manual' # Data from Server (IP range empty or any specific)
                
                if not server_url or not self.agent_ip:
                    return jsonify({"error": "Missing server_url or agent_ip"}), 400

                print(f"Scan type {scan_type} ip range is {ip_range} process mode is {process_mode} type is {scan_type}")
                
                if scan_type not in ['nmap', 'openvas']: 
                    return jsonify({"error": "Invalid scan_type. Must be 'nmap' or 'openvas'"}), 400

                self.logger.info(f"{process_mode.upper()} scan triggered for {scan_type} on range: {ip_range or 'auto'}")

                scan_thread = threading.Thread(
                    target=self.execute_scan,
                    args=(scan_type, ip_range, process_mode,server_url),
                    daemon=True
                )
                scan_thread.start()

                return jsonify({
                    "status": "scan_started",
                    "scan_type": scan_type,
                    "agent_ip":self.agent_ip,
                    "ip_range": ip_range or "auto",
                    "process_mode": process_mode,
                    "message": "Scan initiated successfully",
                    "timestamp": time.time()
                }) ,200

            except Exception as e:
                self.logger.error(f"Error in trigger_scan: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/status', methods=['GET','POST'])
        def get_status():
            return jsonify({
                "status": "active",
                "agent_ip":self.agent_ip,
                "agent_type": "scan_agent",
                "supported_scans": ["nmap", "openvas"],
                "timestamp": time.time()
            })

    def get_real_interfaces(self) -> Optional[Dict[str, list]]:
        """
        Get real physical interfaces like Ethernet/Wi-Fi with valid IPv4 CIDRs.
        Returns: dict {interface_name: [CIDRs]} or None
        """
        cidrs_by_interface = {}

        try:
            interfaces = psutil.net_if_addrs()

            for iface_name, addresses in interfaces.items():
                if any(skip in iface_name.lower() for skip in ["loopback", "bluetooth", "vethernet", "virtual", "wsl", "docker", "hyper-v"]):
                    continue

                cidrs = []
                for addr in addresses:
                    if addr.family == socket.AF_INET and addr.address and addr.netmask:
                        ip = ipaddress.IPv4Address(addr.address)
                        if ip.is_loopback or ip.is_link_local or ip.is_multicast:
                            continue
                        try:
                            network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                            cidrs.append(f"{network.network_address}/{network.prefixlen}")
                        except Exception:
                            continue

                if cidrs:
                    cidrs_by_interface[iface_name] = cidrs
            # print("cidrs : " ,cidrs_by_interface) #....................................debuging

            return cidrs_by_interface if cidrs_by_interface else None

        except Exception as e:
            self.logger.error(f"Error getting interfaces: {e}")
            return None

    def send_result_to_server(self, result_data: Dict ,server_url: str):
        """Send scan results back to the centralized server."""
        """Sending each interface result   status = "scan_completed" if result else "scan_failed"
                            "status": status,
                            "type":"data",
                            "report":"scan_data",
                            "scan_type": scan_type,
                            "agent_ip":agent_ip,
                            "cidr": cidr,
                            "interface": iface,
                            "original_range": "auto",
                            "result": result if result else {"error": f"Scan failed for {cidr}"},
                            "timestamp": time.time()  
                             
                               final summary :  final_status = "full_scan_completed" if overall_success else "full_scan_failed"
                            "status": final_status,
                            "agent_ip": agent_ip,
                            "report":"final_summary",
                            "scan_type": scan_type,
                            "mode": "auto",
                            "timestamp": time.time(),
                            "summary": 
                            {"cidr": cidr,
                            "status": status}  """
        try:
            import requests
            url = server_url
            response = requests.post(url, json=result_data, timeout=30)

            try:
                resp_json = response.json()
            except Exception:
                resp_json = {"error": "Non-JSON response from server"}

            if response.status_code == 200:
                self.logger.info(f"Result sent successfully: {resp_json}")
            else:
                self.logger.error(f" Failed to send result (code {response.status_code}): {resp_json}")

        except Exception as e:
            self.logger.error(f" Error sending result to server: {e}")
    
    

    def send_scan_result(self, scan_type, agent_ip, cidr, result, mode, report_type ,server_url): 
        status = "scan_completed" if result else "scan_failed"
        payload = {
            "status": status,
            "report": report_type,
            "scan_type": scan_type,
            "agent_ip": agent_ip,
            "cidr": cidr,
            "mode": mode,
            "result": result if result else {"error": f"Scan failed for {cidr}"},
            "timestamp": time.time()
        }
        self.send_result_to_server(payload ,server_url)
        return {"cidr": cidr, "status": status}
 
    def execute_scan(self, scan_type: str, ip_range: str, process_mode: str ,server_url: str):
        """
        Execute scan based on mode and type.
        Auto mode scans all CIDRs from real interfaces.
        Manual mode scans the provided CIDR/IP range.
        """
        try:
            self.logger.info(f"Starting scan: type={scan_type}, mode={process_mode}")
            

            if process_mode == 'auto':
                interfaces = self.get_real_interfaces()
                if not interfaces:
                    raise RuntimeError("No valid CIDRs found on any interface")


                overall_success = True
                scan_results = []

                for iface, cidr_list in interfaces.items():
                    for cidr in cidr_list:
                        self.logger.info(f"Scanning CIDR {cidr} on interface {iface}")
                        result = self.perform_single_scan(scan_type, cidr)

                        status_payload = self.send_scan_result(
                            scan_type=scan_type,
                            agent_ip=self.agent_ip,
                            cidr=cidr,
                            result=result,
                            mode="auto",
                            report_type="scan_data",
                            server_url=server_url
                            )
                        
                        if status_payload["status"] == "scan_failed":
                            overall_success = False

                        

                        scan_results.append(status_payload) # cidr ,status dict

                # Send final summary
                final_status = "scan_completed" if overall_success else "scan_failed"
                self.send_result_to_server({
                    "status": final_status,
                    "report":"final_summary",
                    "agent_ip":  self.agent_ip,
                    "scan_type": scan_type,
                    "mode": "auto",
                    "timestamp": time.time(),
                    "summary": scan_results
                },server_url)        

            else:
                self.logger.info(f"Scanning provided range: {ip_range}")
                result = self.perform_single_scan(scan_type, ip_range)

                status_payload = self.send_scan_result(
                    scan_type=scan_type,
                    agent_ip=self.agent_ip,
                    cidr=ip_range,
                    result=result,
                    mode="manual",
                    report_type="scan_data",
                    server_url=server_url
                    )
                
                
                # final Summary
                self.send_result_to_server({
                "status": status_payload["status"],
                "report": "final_summary",
                "agent_ip": self.agent_ip,
                "scan_type": scan_type,
                "mode": "manual",
                "timestamp": time.time(),
                "summary": [status_payload]
            },server_url)

        except Exception as e:
            self.logger.error(f"Error executing scan: {e}")
            self.send_result_to_server({
                "status": "scan_failed",
                "report": "error",
                "scan_type": scan_type,
                "agent_ip": self.agent_ip,
                "ip_range": ip_range if ip_range else "",
                "error": str(e),
                "timestamp": time.time()
                } ,server_url)

    def perform_single_scan(self, scan_type: str, target: str) -> Optional[Dict]:
        """Perform a single scan on the specified target CIDR or IP."""
        try:
            self.logger.info(f"Executing {scan_type} scan on {target}")

            if scan_type == 'nmap':
                result = self.nmap_scanner.run(target)
                return {
                        "scan_type": "nmap",
                        "cidr": target,
                        "result": result }

            elif scan_type == 'openvas':
                import asyncio
                result = asyncio.run(self.openvas_scanner.run(target))
                return {
                        "scan_type": "openvas",
                        "cidr": target,
                        "result": result }

            else:
                self.logger.error(f"Unsupported scan type: {scan_type}")
                return None

         
        except Exception as e:
            self.logger.error(f"Error performing {scan_type} scan on {target}: {e}")
            return None

    def start_agent(self, host: str = "0.0.0.0", port: int = 7000):
        """Start the Flask server."""
        try:
            self.logger.info(f"Starting ScanAgent server on {host}:{port}")
            self.app.run(host=host, port=port, debug=True, threaded=True)
        except Exception as e:
            self.logger.error(f"Error starting agent server: {e}")


def main():
    agent = ScanAgent()
    agent.start_agent()


if __name__ == "__main__":
    main()
