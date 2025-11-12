import os
import json
from datetime import datetime
from xml.etree import ElementTree as etree

from dotenv import load_dotenv
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
import xmltodict




def _ensure_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def parse_openvas_xml_to_ip_map(xml_content: str) -> dict:
    """Parse OpenVAS XML report to a dict keyed by IP with consolidated info."""
    result = {}
    try:
        root = etree.fromstring(xml_content)
    except Exception:
        return result

    report = root.find('.//report')
    if report is None:
        return result

    # Initialize hosts seen in <host> blocks
    for host_el in report.findall('.//host'):
        ip = (host_el.findtext('ip', '') or '').strip()
        if not ip:
            continue
        if ip not in result:
            result[ip] = {
                'ip_address': ip,
                'hostname': None,
                'mac_address': None,
                'operating_system': None,
                'cpe':None,
                'open_ports': {
                    'tcp': [],
                    'udp': []
                },
                'vulnerabilities': [],
                'misconfigurations': [],
                'solutions_and_mitigations': [],
                'cves': []
            }

        # Collect host details
        for detail in host_el.findall('.//detail'):
            name = (detail.findtext('name', '') or '').strip().lower()
            value = (detail.findtext('value', '') or '').strip()
            if not value or value.lower() in ['unknown', '0', 'n/a']:
                continue
            if name == 'mac':
                result[ip]['mac_address'] = value
            elif name == 'os':
                result[ip]['cpe'] = value
            elif name == 'best_os_txt':
                result[ip]['operating_system'] = value
            elif name == 'hostname':
                result[ip]['hostname'] = value
            elif name == 'tcp_ports':
                try:
                    ports = [int(p.strip()) for p in value.split(',') if p.strip().isdigit()]
                    result[ip]['open_ports']['tcp'] = sorted(list(set(result[ip]['open_ports']['tcp'] + ports)))
                except Exception:
                    pass
            elif name == 'udp_ports':
                try:
                    ports = [int(p.strip()) for p in value.split(',') if p.strip().isdigit()]
                    result[ip]['open_ports']['udp'] = sorted(list(set(result[ip]['open_ports']['udp'] + ports)))
                except Exception:
                    pass

    # Process results/vulnerabilities
    for res in report.findall('.//results/result'):
        host_ip = res.findtext('host', 'N/A')
        if host_ip not in result:
            continue

        port = res.findtext('port', 'N/A')
        threat = res.findtext('threat', 'N/A')
        try:
            severity = float(res.findtext('severity', '0.0'))
        except Exception:
            severity = 0.0

        nvt = res.find('nvt')
        vuln_name = (nvt.findtext('name', 'Unknown') if nvt is not None else 'Unknown')
        cvss_vector = (nvt.findtext('cvss_base_vector', 'N/A') if nvt is not None else 'N/A')
        cvss_base_text = (nvt.findtext('cvss_base', None) if nvt is not None else None)
        try:
            cvss_base_score = float(cvss_base_text) if cvss_base_text is not None else None
        except Exception:
            cvss_base_score = None

        description = (res.findtext('description', '') or '').strip()

        # Collect CVEs (skip generic references)
        cves = []
        family = (nvt.findtext('family', '') if nvt is not None else '')
        refs = nvt.find('refs') if nvt is not None else None
        if refs is not None:
            for ref in refs.findall('ref'):
                ref_type = ref.get('type', '')
                ref_id = ref.get('id', '')
                if ref_type == 'cve' and ref_id:
                    cves.append(ref_id)

        # Extract solution/mitigation hints from tags (no inference)
        solution_desc = 'N/A'
        solution_type = 'N/A'
        tags_text = nvt.findtext('tags', '') if nvt is not None else ''
        if tags_text:
            try:
                tag_dict = {}
                for item in tags_text.split('|'):
                    if '=' in item:
                        k, v = item.split('=', 1)
                        tag_dict[k.strip()] = v.strip()
                solution_desc = tag_dict.get('solution', solution_desc)
                solution_type = tag_dict.get('solution_type', solution_type)
            except Exception:
                pass

        vuln_entry = {
            'name': vuln_name,
            'risk': threat,
            'severity_score': severity,
            'cvss_vector': cvss_vector,
            'cvss_base_score': cvss_base_score,
            'family': family,
            'description': description,
            'port_protocol': port,
            'cves': cves,
            'solution': {
                'type': solution_type,
                'description': solution_desc
            }
        }

        result[host_ip]['vulnerabilities'].append(vuln_entry)
        result[host_ip]['cves'] = sorted(list(set(result[host_ip]['cves'] + cves)))

        # Collect host-level solutions_and_mitigations directly from parsed solution
        if solution_desc and solution_desc != 'N/A':
            sol_item = {
                'name': vuln_name,
                'port_protocol': port,
                'solution': solution_desc
            }
            # Prevent duplicates
            exists = any(
                s.get('name') == sol_item['name'] and
                s.get('port_protocol') == sol_item['port_protocol'] and
                s.get('solution') == sol_item['solution']
                for s in result[host_ip]['solutions_and_mitigations']
            )
            if not exists:
                result[host_ip]['solutions_and_mitigations'].append(sol_item)

        # Minimal, string-based classification of misconfigurations from explicit text
        name_l = (vuln_name or '').lower()
        family_l = (family or '').lower()
        if (
            'misconfig' in name_l
            or 'default' in name_l
            or 'weak' in name_l
            or 'insecure' in name_l
            or 'config' in name_l
            or 'anonymous' in name_l
            or 'misconfig' in family_l
            or 'configuration' in family_l
            or 'policy' in family_l
        ):
            result[host_ip]['misconfigurations'].append(vuln_entry)

    # Final tidy
    for ip, host in result.items():
        host['open_ports']['tcp'] = sorted(list(set(host['open_ports']['tcp'])))
        host['open_ports']['udp'] = sorted(list(set(host['open_ports']['udp'])))

    return result


def parse_openvas_json_file_to_ip_map(json_file_path: str) -> dict:
    """Load xmltodict JSON dump and convert via the XML path if possible."""
    try:
        with open(json_file_path, 'r', encoding='utf-8') as jf:
            data = json.load(jf)
    except Exception:
        return {}

    # Re-serialize to XML-ish string then reuse the XML parser for consistency
    # The xmltodict structure should have a single root; find the first key
    try:
        root_key = next(iter(data.keys()))
        # Convert back to XML string using a minimal approach
        # Prefer to read sibling XML if exists with same stem
        xml_candidate = json_file_path[:-5] + '.xml'
        if os.path.exists(xml_candidate):
            with open(xml_candidate, 'r', encoding='utf-8') as xf:
                return parse_openvas_xml_to_ip_map(xf.read())
    except Exception:
        pass

    # Fallback: try to find report text inside JSON and dump to XML using xmltodict.unparse
    try:
        xml_text = xmltodict.unparse(data, pretty=True)
        return parse_openvas_xml_to_ip_map(xml_text)
    except Exception:
        return {}


def fetch_and_save_report(report_or_task_id: str) -> str:
    """Fetch an OpenVAS report by ID and save the raw XML to Data/.

    Returns the saved file path on success, or raises on error.
    """
    load_dotenv()

    host = os.getenv("OPENVAS_HOST", "localhost")
    port = int(os.getenv("OPENVAS_PORT", 9390))
    username = os.getenv("OPENVAS_USERNAME", "admin")
    password = os.getenv("OPENVAS_PASSWORD", "admin")

    # XML report format (same as used in openvas_agent.py)
    report_format_id = "a994b278-1f62-11e1-96ac-406186ea4fc5"

    # Ensure output directory exists
    data_dir = os.path.join(os.path.dirname(__file__), "Data")
    os.makedirs(data_dir, exist_ok=True)

    # Build destination file path
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_id = report_or_task_id.replace("/", "_")
    out_path = os.path.join(data_dir, f"openvas_raw_report_{safe_id}_{timestamp}.xml")
    json_out_path = out_path[:-4] + ".json"

    # Connect and fetch report
    connection = TLSConnection(hostname=host, port=port)
    with Gmp(connection) as gmp:
        gmp.authenticate(username, password)

        # Try fetching as a Report ID first
        def get_report_xml_by_id(rid: str) -> str:
            return gmp.get_report(
                report_id=rid,
                report_format_id=report_format_id,
                details=True,
                ignore_pagination=True,
            )

        raw_report_xml = get_report_xml_by_id(report_or_task_id)

        # If server responds with error, try to resolve as Task ID -> Report ID
        try:
            tmp_obj = xmltodict.parse(raw_report_xml)
            root_key = next(iter(tmp_obj.keys())) if tmp_obj else None
            status = None
            if root_key and isinstance(tmp_obj[root_key], dict):
                status = tmp_obj[root_key].get("@status")
            if status and str(status).startswith("4"):
                # Try interpret input as Task ID and resolve last report id
                task_xml = gmp.get_task(report_or_task_id)
                task_tree = etree.fromstring(task_xml)
                last_report = task_tree.find('.//last_report/report')
                resolved_report_id = last_report.get('id') if last_report is not None else None
                if not resolved_report_id:
                    raise RuntimeError("Could not resolve report id from task")
                raw_report_xml = get_report_xml_by_id(resolved_report_id)
        except Exception:
            # Keep the original raw_report_xml as-is
            pass

        # Optionally validate XML and also convert to JSON
        parsed_ok = True
        try:
            etree.fromstring(raw_report_xml)
        except Exception:
            # If it isn't strictly well-formed, still save raw content for troubleshooting
            parsed_ok = False

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(raw_report_xml)

        # If we successfully parsed XML, emit a JSON sibling using xmltodict
        if parsed_ok:
            obj = xmltodict.parse(raw_report_xml)
            with open(json_out_path, "w", encoding="utf-8") as jf:
                json.dump(obj, jf, indent=2)

    return out_path


if __name__ == "__main__":
    try:
        data_dir = os.path.join(os.path.dirname(__file__), "Data")
        os.makedirs(data_dir, exist_ok=True)

        print("Select an option:")
        print("  1) Fetch report by Report ID or Task ID and save")
        print("  2) Process an existing saved XML/JSON file in Data/ to consolidated JSON keyed by IP")
        choice = input("Enter 1 or 2: ").strip()

        if choice == '1':
            report_id_input = input("Enter the OpenVAS Report ID or Task ID: ").strip()
            if not report_id_input:
                print("No Report/Task ID provided. Exiting.")
                raise SystemExit(1)
            saved_path = fetch_and_save_report(report_id_input)
            print(f"Report saved to: {saved_path}")

            # Ask if user wants to immediately process the saved file
            process_now = input("Process this saved XML into consolidated JSON now? (y/N): ").strip().lower()
            if process_now == 'y':
                with open(saved_path, 'r', encoding='utf-8') as f:
                    xml_text = f.read()
                ip_map = parse_openvas_xml_to_ip_map(xml_text)
                out_json = os.path.join(data_dir, 'Openvas_summary_scan.json')
                with open(out_json, 'w', encoding='utf-8') as of:
                    json.dump(ip_map, of, indent=2)
                print(f"Consolidated JSON saved to: {out_json}")
                # Display concise summary to console
                for ip, host in ip_map.items():
                    print(f"\nHost: {ip}")
                    if host.get('hostname'):
                        print(f"  Hostname: {host['hostname']}")
                    if host.get('operating_system'):
                        print(f"  OS: {host['operating_system']}")
                    tcp = ','.join(map(str, host['open_ports'].get('tcp', [])))
                    udp = ','.join(map(str, host['open_ports'].get('udp', [])))
                    if tcp:
                        print(f"  TCP: {tcp}")
                    if udp:
                        print(f"  UDP: {udp}")
                    print(f"  Vulns: {len(host.get('vulnerabilities', []))}")

        elif choice == '2':
            # List files
            files = [fn for fn in os.listdir(data_dir) if fn.lower().endswith(('.xml', '.json'))]
            files.sort()
            if not files:
                print("No XML/JSON files found in Data/.")
                raise SystemExit(1)
            print("Select a file to process:")
            for i, fn in enumerate(files, 1):
                print(f"  {i}) {fn}")
            idx = input("Enter number: ").strip()
            if not idx.isdigit() or int(idx) < 1 or int(idx) > len(files):
                print("Invalid selection.")
                raise SystemExit(1)
            selected = os.path.join(data_dir, files[int(idx) - 1])
            if selected.lower().endswith('.xml'):
                with open(selected, 'r', encoding='utf-8') as f:
                    xml_text = f.read()
                ip_map = parse_openvas_xml_to_ip_map(xml_text)
            else:
                ip_map = parse_openvas_json_file_to_ip_map(selected)

            out_json = os.path.join(data_dir, 'processed_scan_openvas_hard.json')
            with open(out_json, 'w', encoding='utf-8') as of:
                json.dump(ip_map, of, indent=2)
            print(f"Consolidated JSON saved to: {out_json}")
            # Display concise summary to console
            for ip, host in ip_map.items():
                print(f"\nHost: {ip}")
                if host.get('hostname'):
                    print(f"  Hostname: {host['hostname']}")
                if host.get('operating_system'):
                    print(f"  OS: {host['operating_system']}")
                tcp = ','.join(map(str, host['open_ports'].get('tcp', [])))
                udp = ','.join(map(str, host['open_ports'].get('udp', [])))
                if tcp:
                    print(f"  TCP: {tcp}")
                if udp:
                    print(f"  UDP: {udp}")
                print(f"  Vulns: {len(host.get('vulnerabilities', []))}")

        else:
            print("Invalid option.")
            raise SystemExit(1)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as exc:
        print(f"Failed: {exc}")

