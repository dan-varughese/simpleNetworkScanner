import nmap
import sys

def scan_network(target, ports=None, script_args=None, aggressive=False):
    """
    Scans a network target for open ports, services, and potential vulnerabilities.

    Args:
        target: The target IP address or network range (e.g., "192.168.1.1", "192.168.1.0/24").
        ports: A string specifying the ports to scan (e.g., "22-1024", "80,443").  If None, a default scan is performed.
        script_args: Additional arguments to pass to Nmap scripts (e.g., "--script vuln").
        aggressive: Boolean indicating whether to perform an aggressive scan (more thorough but slower).

    Returns:
        A dictionary containing the scan results, or None if an error occurred.
    """
    try:
        nm = nmap.PortScanner()
        scan_args = ""

        if ports:
            scan_args += f"-p {ports} "
        if script_args:
            scan_args += f"{script_args} "

        if aggressive:
            scan_args += "-A " # Aggressive scan: OS detection, version detection, script scanning

        nm.scan(hosts=target, arguments=scan_args)

        results = {
            'target': target,
            'open_ports': [],
            'services': {},
            'vulnerabilities': []
        }

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    results['open_ports'].append(port)
                    service = nm[host][proto][port]['name']
                    results['services'][port] = service

                    #Check for vulnerabilities from Nmap scripts
                    if 'script' in nm[host][proto][port]:
                        for script_output in nm[host][proto][port]['script'].values():
                            if "vulnerable" in script_output.lower() or "risk" in script_output.lower():
                                results['vulnerabilities'].append(f"Port {port} ({service}): {script_output.strip()}")

        return results

    except nmap.PortScannerError as e:
        print(f"Error during scan: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python network_scanner.py <target> [ports] [script_args] [-a]")
        print("  <target>: IP address or network range (e.g., 192.168.1.1, 192.168.1.0/24)")
        print("  [ports]: Ports to scan (e.g., 22-1024, 80,443).  Defaults to a basic scan if omitted.")
        print("  [script_args]: Additional Nmap script arguments (e.g., --script vuln).")
        print("  -a: Perform an aggressive scan (more thorough, slower).")
        sys.exit(1)


    target = sys.argv[1]
    ports = sys.argv[2] if len(sys.argv) > 2 else None
    script_args = sys.argv[3] if len(sys.argv) > 3 else None
    aggressive = '-a' in sys.argv

    results = scan_network(target, ports, script_args, aggressive)
    if results:
        print(f"Scan results for {results['target']}:")
        print("Open Ports:", results['open_ports'])
        print("\nServices:")
        for port, service in results['services'].items():
            print(f"  Port {port}: {service}")
        if results['vulnerabilities']:
            print("\nPotential Vulnerabilities:")
            for vuln in results['vulnerabilities']:
                print(f"  - {vuln}")
        else:
            print("\nNo potential vulnerabilities detected (based on the run scripts).")