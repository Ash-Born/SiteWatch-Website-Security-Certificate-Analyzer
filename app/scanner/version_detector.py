import re

class VersionDetector:
    def detect(self, banner: str) -> dict:
        """Analyze a service banner to detect the software name and version.
        
        Returns a dictionary with 'software' and 'version' keys.
        """
        if not banner:
            return {
                "software": "unknown",
                "version": "unknown"
            }

        # Normalize line endings and strip whitespace
        banner_str = banner.strip()
        
        # 1. SSH Detection
        # Format: SSH-protoversion-softwareversion comments
        # Example: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
        # Example: SSH-2.0-dropbear_2020.81
        ssh_match = re.search(r'^SSH-\d+\.\d+-([a-zA-Z0-9_\-]+)_([a-zA-Z0-9\.\-]+)', banner_str, re.IGNORECASE)
        if ssh_match:
            return {
                "software": ssh_match.group(1),
                "version": ssh_match.group(2)
            }
        
        ssh_match_alt = re.search(r'^SSH-\d+\.\d+-([a-zA-Z0-9_\-]+)\s+([a-zA-Z0-9\.\-]+)', banner_str, re.IGNORECASE)
        if ssh_match_alt:
            return {
                "software": ssh_match_alt.group(1),
                "version": ssh_match_alt.group(2)
            }

        # 2. HTTP Server header Detection
        # Check for HTTP headers, look for Server: <software>/<version>
        # Example: Server: Apache/2.4.7 (Ubuntu)
        # Example: Server: nginx/1.18.0
        # Example: Server: Microsoft-IIS/10.0
        # Example: Server: Werkzeug/2.0.1 Python/3.8.10
        # Example: HTTP/1.1 200 OK\r\nServer: Apache/2.4.7 ...
        for line in banner_str.splitlines():
            # Check for "Server: " header
            server_match = re.search(r'^Server:\s*([a-zA-Z0-9_\-\(\)\s]+)/([a-zA-Z0-9\.\-]+)', line, re.IGNORECASE)
            if server_match:
                software = server_match.group(1).strip()
                # Clean up any trailing comments like (Ubuntu) or (Unix) from software name if they got parsed
                software = re.sub(r'\s*\(.*\)', '', software).strip()
                version = server_match.group(2).strip()
                return {
                    "software": software,
                    "version": version
                }
            
            # Match Server header without version but has some letters
            server_match_no_ver = re.search(r'^Server:\s*([a-zA-Z0-9_\-\s]+)', line, re.IGNORECASE)
            if server_match_no_ver:
                software = server_match_no_ver.group(1).strip()
                if software and not software.lower().startswith("http/"):
                    return {
                        "software": software,
                        "version": "unknown"
                    }

        # 3. FTP Detection
        # Example: 220 (vsFTPd 3.0.3)
        # Example: 220 ProFTPD 1.3.5 Server
        # Example: 220 Pure-FTPd [server reboot]
        if "FTP" in banner_str.upper() or "220" in banner_str:
            vsftpd_match = re.search(r'vsFTPd\s*([a-zA-Z0-9\.\-]+)?', banner_str, re.IGNORECASE)
            if vsftpd_match:
                version = vsftpd_match.group(1) if vsftpd_match.group(1) else "unknown"
                return {"software": "vsFTPd", "version": version}
            
            proftpd_match = re.search(r'ProFTPD\s*([a-zA-Z0-9\.\-]+)', banner_str, re.IGNORECASE)
            if proftpd_match:
                return {"software": "ProFTPD", "version": proftpd_match.group(1)}
            
            pureftpd_match = re.search(r'Pure-FTPd', banner_str, re.IGNORECASE)
            if pureftpd_match:
                return {"software": "Pure-FTPd", "version": "unknown"}

        # 4. SMTP Detection
        # Example: 220 mail.example.com ESMTP Postfix
        # Example: 220 mail.example.com ESMTP Exim 4.93
        if "ESMTP" in banner_str.upper() or "SMTP" in banner_str.upper():
            postfix_match = re.search(r'Postfix', banner_str, re.IGNORECASE)
            if postfix_match:
                return {"software": "Postfix", "version": "unknown"}
            exim_match = re.search(r'Exim\s+([a-zA-Z0-9\.\-]+)', banner_str, re.IGNORECASE)
            if exim_match:
                return {"software": "Exim", "version": exim_match.group(1)}
            sendmail_match = re.search(r'Sendmail\s+([a-zA-Z0-9\.\-]+)', banner_str, re.IGNORECASE)
            if sendmail_match:
                return {"software": "Sendmail", "version": sendmail_match.group(1)}

        # 5. MySQL / Database Detection
        # MySQL banner starts with protocol version or direct version
        # Example: 5.7.33-0ubuntu0.18.04.1
        # Example: 8.0.25
        mysql_match = re.search(r'(\d+\.\d+\.\d+)-([a-zA-Z0-9\.\-]+)?-?(MariaDB|MySQL)?', banner_str, re.IGNORECASE)
        if mysql_match:
            version = mysql_match.group(1)
            software = "MySQL/MariaDB"
            if mysql_match.group(3):
                software = mysql_match.group(3)
            elif "mariadb" in banner_str.lower():
                software = "MariaDB"
            elif "mysql" in banner_str.lower():
                software = "MySQL"
            return {"software": software, "version": version}

        # Fallback generic pattern matching for "<software>/<version>" or "<software> <version>"
        # e.g. "Apache/2.4.41"
        generic_match = re.search(r'([a-zA-Z0-9_\-]+)/([0-9\.]+)', banner_str)
        if generic_match:
            return {
                "software": generic_match.group(1),
                "version": generic_match.group(2)
            }

        return {
            "software": "unknown",
            "version": "unknown"
        }