"""
Safe Nmap Scanner Wrapper for VAPT-GPT Sentinel.
Executes non-intrusive service and banner discovery using strictly safe scripts.
Prohibits aggressive exploitation flags (-A, --script=exploit, etc.).
"""

import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

from sentinel.scanners.base import BaseScanner


class NmapScanner(BaseScanner):
    """Wraps Nmap in strictly safe non-intrusive banner discovery mode."""

    tool_name = "nmap"

    SAFE_SCRIPTS = ["banner", "http-title", "ssl-cert"]
    PROHIBITED_FLAGS = ["-A", "--script=exploit", "--script=vuln", "--os-shell"]

    def _find_nmap_bin(self) -> Optional[str]:
        direct = shutil.which("nmap")
        if direct:
            return direct
        common_paths = [
            r"D:\ZENMAP\Nmap\nmap.exe",
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ]
        for p in common_paths:
            if Path(p).exists():
                return p
        return None

    def _socket_fallback_scan(self, host: str, ports: List[int]) -> Dict[str, Any]:
        """Safe non-intrusive socket port & banner grabber fallback."""
        open_ports = []
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            try:
                res = s.connect_ex((host, port))
                if res == 0:
                    banner = ""
                    try:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(512).decode("utf-8", errors="ignore").splitlines()[0]
                    except Exception:
                        pass
                    open_ports.append(
                        {
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "http"
                            if port in (80, 8080, 8081, 8082, 3000)
                            else "unknown",
                            "banner": banner,
                        }
                    )
            except Exception:
                pass
            finally:
                s.close()
        return {"host": host, "ports": open_ports, "engine": "socket_fallback"}

    def run(self, target: str, run_id: str, **kwargs: Any) -> Dict[str, Any]:
        """Runs safe nmap banner scan against the target host."""
        # Normalize target to host
        host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        ports_list = kwargs.get("ports", [8080, 8081, 8082, 80, 443])
        ports_str = ",".join(str(p) for p in ports_list)

        nmap_bin = self._find_nmap_bin()
        if not nmap_bin:
            return self._socket_fallback_scan(host, ports_list)

        cmd = [
            nmap_bin,
            "-sV",
            "-T4",
            "--script=banner",
            "-p",
            ports_str,
            host,
            "-oX",
            "-",
        ]

        # Verify no prohibited flags are present
        for arg in cmd:
            if any(prohibited in arg for prohibited in self.PROHIBITED_FLAGS):
                raise ValueError(f"Prohibited scanner flag detected: {arg}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            xml_output = result.stdout.strip()
            if not xml_output or not xml_output.startswith("<?xml"):
                return self._socket_fallback_scan(host, ports_list)

            # Parse XML output
            root = ET.fromstring(xml_output)
            ports_data = []
            for port_elem in root.findall(".//port"):
                port_id = int(port_elem.attrib.get("portid", 0))
                proto = port_elem.attrib.get("protocol", "tcp")
                state_elem = port_elem.find("state")
                state = (
                    state_elem.attrib.get("state", "unknown")
                    if state_elem is not None
                    else "unknown"
                )
                service_elem = port_elem.find("service")
                service_name = (
                    service_elem.attrib.get("name", "unknown")
                    if service_elem is not None
                    else "unknown"
                )
                product = service_elem.attrib.get("product", "") if service_elem is not None else ""
                version = service_elem.attrib.get("version", "") if service_elem is not None else ""

                banner = f"{product} {version}".strip()
                ports_data.append(
                    {
                        "port": port_id,
                        "protocol": proto,
                        "state": state,
                        "service": service_name,
                        "banner": banner,
                    }
                )

            return {"host": host, "ports": ports_data, "engine": "nmap_xml"}
        except Exception:
            return self._socket_fallback_scan(host, ports_list)

    def parse(self, raw_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parses discovered open ports into findings."""
        data = raw_output.get("data", {})
        ports = data.get("ports", [])
        parsed: List[Dict[str, Any]] = []

        for p in ports:
            if p.get("state") == "open":
                port = p.get("port")
                service = p.get("service")
                banner = p.get("banner", "")
                parsed.append(
                    {
                        "tool": "nmap",
                        "title": f"Open Port {port}/tcp ({service})",
                        "severity": "INFO",
                        "cwe": "CWE-200",  # Exposure of Sensitive Information
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "evidence": f"Port {port}/tcp is open running {service}. Banner: {banner}",
                    }
                )

        return parsed
