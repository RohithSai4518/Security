"""
Unified Command-Line Interface for PySecSuite.
"""

import argparse
import sys
import os
import json
import dataclasses

from secsuite.core.logger import logger
from secsuite.core.reporter import ReportGenerator
from secsuite.scanner.port_scanner import PortScanner
from secsuite.scanner.ssl_checker import SSLChecker
from secsuite.scanner.subnet_sweeper import SubnetSweeper
from secsuite.crypto.hash_manager import HashManager
from secsuite.crypto.symmetric import SymmetricCipher
from secsuite.crypto.key_gen import KeyGenerator
from secsuite.ids.log_analyzer import LogAnalyzer
from secsuite.web.headers_auditor import HeadersAuditor
from secsuite.web.url_fuzzer import URLFuzzer
from secsuite.web.mock_target import SandboxServer

def print_banner():
    banner = r"""
===================================================================
  ____        ____            ____        _ _       
 |  _ \ _   _/ ___|  ___  ___/ ___| _   _(_) |_ ___ 
 | |_) | | | \___ \ / _ \/ __\___ \| | | | | __/ _ \
 |  __/| |_| |___) |  __/ (__ ___) | |_| | | ||  __/
 |_|    \__, |____/ \___|\___|____/ \__,_|_|\__\___|
        |___/    Modular Security & Threat Suite (v1.0.0)
===================================================================
    """
    print(f"\033[96m{banner}\033[0m")

def handle_scan(args):
    scanner = PortScanner(target=args.target, timeout=args.timeout, max_threads=args.threads)
    ports = [int(p.strip()) for p in args.ports.split(",")] if args.ports else None
    report = scanner.scan(ports=ports)
    
    rep_gen = ReportGenerator()
    data_dict = dataclasses.asdict(report)
    summary = {
        "Target Host": report.target_host,
        "Target IP": report.target_ip,
        "Total Ports Scanned": report.total_ports_scanned,
        "Open Ports Found": len(report.open_ports),
        "Scan Duration (s)": report.duration_seconds
    }
    
    if args.export:
        rep_gen.save_html("port_scan", f"Port Scan Report - {report.target_host}", summary, data_dict)
        rep_gen.save_json("port_scan", data_dict)
        logger.success(f"Reports saved in 'reports/' directory.")

def handle_ssl(args):
    checker = SSLChecker(host=args.host, port=args.port)
    cert = checker.check_certificate()
    rep_gen = ReportGenerator()
    data_dict = dataclasses.asdict(cert)
    summary = {
        "Host": f"{args.host}:{args.port}",
        "TLS Version": cert.tls_version,
        "Cipher Suite": cert.cipher_suite,
        "Days Until Expiry": cert.days_until_expiry,
        "Is Expired": cert.is_expired,
        "Self Signed": cert.is_self_signed
    }
    if args.export:
        rep_gen.save_html("ssl_check", f"SSL/TLS Certificate Audit - {args.host}", summary, data_dict)
        logger.success(f"Reports saved in 'reports/' directory.")

def handle_crypto(args):
    if args.action == "hash":
        if args.file:
            res = HashManager.multi_hash_file(args.file)
            print(json.dumps(res, indent=2))
        elif args.text:
            res = HashManager.multi_hash_text(args.text)
            print(json.dumps(res, indent=2))
        else:
            logger.error("Specify --text or --file to hash.")
    elif args.action == "encrypt":
        if not args.text or not args.key:
            logger.error("Encryption requires --text and --key (passphrase).")
            return
        token = SymmetricCipher.encrypt(args.text, args.key)
        logger.success("Encrypted Payload Token:")
        print(token)
    elif args.action == "decrypt":
        if not args.text or not args.key:
            logger.error("Decryption requires --text (token) and --key (passphrase).")
            return
        try:
            pt = SymmetricCipher.decrypt(args.text, args.key)
            logger.success("Decrypted Plaintext:")
            print(pt)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
    elif args.action == "genpass":
        pwd = KeyGenerator.generate_complex_password(length=args.length)
        entropy = KeyGenerator.calculate_entropy(pwd)
        logger.success(f"Generated Password: {pwd}")
        logger.info(f"Strength: {entropy['strength']} ({entropy['entropy_bits']} bits entropy)")

def handle_ids(args):
    analyzer = LogAnalyzer(brute_force_threshold=args.threshold)
    res = analyzer.analyze_file(args.file)
    rep_gen = ReportGenerator()
    summary = {
        "Analyzed File": res["file"],
        "Lines Processed": res["lines_processed"],
        "Total Alerts": res["alert_count"],
        "Critical Alerts": res["severity_summary"]["CRITICAL"],
        "High Alerts": res["severity_summary"]["HIGH"],
        "Medium Alerts": res["severity_summary"]["MEDIUM"]
    }
    if args.export:
        rep_gen.save_html("ids_audit", f"IDS Log Analysis Report - {os.path.basename(args.file)}", summary, res)
        rep_gen.save_json("ids_audit", res)
        logger.success("IDS Report generated successfully.")

def handle_web(args):
    if args.action == "headers":
        auditor = HeadersAuditor()
        res = auditor.audit(args.url)
        if args.export:
            rep_gen = ReportGenerator()
            summary = {
                "Target URL": res.url,
                "Status Code": res.status_code,
                "Security Score": f"{res.score_percentage}%",
                "Security Grade": res.grade,
                "Missing Headers": len(res.missing_security_headers),
                "Info Leaks": len(res.information_leaks)
            }
            rep_gen.save_html("web_headers", f"HTTP Headers Audit - {res.url}", summary, dataclasses.asdict(res))
            logger.success("Web Header Report generated in reports/")
    elif args.action == "fuzz":
        fuzzer = URLFuzzer(base_url=args.url)
        fuzzer.scan()
    elif args.action == "sandbox":
        server = SandboxServer(port=args.port)
        logger.info(f"Starting Sandbox Mock Target HTTP server on http://127.0.0.1:{args.port}...")
        logger.info("Press Ctrl+C to terminate sandbox server.")
        server.start()
        try:
            while True:
                pass
        except KeyboardInterrupt:
            server.stop()
            logger.info("Sandbox server stopped.")

def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PySecSuite - Modular Security & Threat Analysis Suite")
    subparsers = parser.add_subparsers(dest="command", help="Module commands")

    # Scanner Subcommand
    scan_p = subparsers.add_parser("scan", help="TCP Port & Service Scanner")
    scan_p.add_argument("target", help="Target hostname or IP address")
    scan_p.add_argument("-p", "--ports", help="Comma-separated list of ports (e.g. 22,80,443)")
    scan_p.add_argument("-t", "--threads", type=int, default=30, help="Max worker threads")
    scan_p.add_argument("--timeout", type=float, default=1.0, help="Connection timeout in seconds")
    scan_p.add_argument("--export", action="store_true", help="Generate HTML & JSON reports")

    # SSL Checker Subcommand
    ssl_p = subparsers.add_parser("ssl", help="TLS/SSL Certificate Validator")
    ssl_p.add_argument("host", help="Target domain (e.g. example.com)")
    ssl_p.add_argument("-p", "--port", type=int, default=443, help="Port (default: 443)")
    ssl_p.add_argument("--export", action="store_true", help="Generate report")

    # Crypto Subcommand
    crypto_p = subparsers.add_parser("crypto", help="Cryptographic Tools (Hashing, Encryption, Keys)")
    crypto_p.add_argument("action", choices=["hash", "encrypt", "decrypt", "genpass"], help="Crypto operation")
    crypto_p.add_argument("-t", "--text", help="Plaintext or token string")
    crypto_p.add_argument("-f", "--file", help="File to hash")
    crypto_p.add_argument("-k", "--key", help="Passphrase for symmetric encryption")
    crypto_p.add_argument("-l", "--length", type=int, default=16, help="Password length")

    # IDS Subcommand
    ids_p = subparsers.add_parser("ids", help="Log Analyzer & Intrusion Detection System")
    ids_p.add_argument("file", help="Path to access or auth log file")
    ids_p.add_argument("--threshold", type=int, default=5, help="Brute-force login threshold")
    ids_p.add_argument("--export", action="store_true", help="Generate HTML & JSON reports")

    # Web Subcommand
    web_p = subparsers.add_parser("web", help="Web Security Auditor & Sandbox")
    web_p.add_argument("action", choices=["headers", "fuzz", "sandbox"], help="Web security action")
    web_p.add_argument("-u", "--url", help="Target URL (e.g. http://127.0.0.1:8888)")
    web_p.add_argument("-p", "--port", type=int, default=8888, help="Sandbox server port")
    web_p.add_argument("--export", action="store_true", help="Generate report")

    return parser

def main():
    print_banner()
    parser = build_cli_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    if args.command == "scan":
        handle_scan(args)
    elif args.command == "ssl":
        handle_ssl(args)
    elif args.command == "crypto":
        handle_crypto(args)
    elif args.command == "ids":
        handle_ids(args)
    elif args.command == "web":
        handle_web(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
