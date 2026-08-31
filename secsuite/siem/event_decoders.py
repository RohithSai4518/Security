"""
SIEM Multi-Format Event Decoders, Normalizers, and Field Parsers.
Standardizes heterogeneous log messages into normalized security telemetry schemas.
"""

import re
from dataclasses import dataclass
from typing import Dict, Any, Optional, List

@dataclass
class DecoderDefinition:
    decoder_id: str
    log_source: str
    event_type: str
    regex_pattern: str
    compiled_regex: re.Pattern
    field_mapping: Dict[str, str]
    description: str

SIEM_DECODER_REGISTRY: Dict[str, DecoderDefinition] = {
    "DEC-APACHE_ERROR-0001": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0001",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1)"
    ),
    "DEC-LINUX_AUTH-0002": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0002",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #2)"
    ),
    "DEC-WIN_EVENT_4624-0003": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0003",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #3)"
    ),
    "DEC-WIN_EVENT_4625-0004": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0004",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #4)"
    ),
    "DEC-AWS_CLOUDTRAIL-0005": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0005",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #5)"
    ),
    "DEC-GCP_AUDIT-0006": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0006",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #6)"
    ),
    "DEC-CISCO_ASA-0007": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0007",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #7)"
    ),
    "DEC-SURICATA_EVE-0008": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0008",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #8)"
    ),
    "DEC-POSTGRES_AUDIT-0009": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0009",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #9)"
    ),
    "DEC-NGINX_ACCESS-0010": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0010",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #10)"
    ),
    "DEC-APACHE_ERROR-0011": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0011",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #11)"
    ),
    "DEC-LINUX_AUTH-0012": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0012",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #12)"
    ),
    "DEC-WIN_EVENT_4624-0013": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0013",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #13)"
    ),
    "DEC-WIN_EVENT_4625-0014": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0014",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #14)"
    ),
    "DEC-AWS_CLOUDTRAIL-0015": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0015",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #15)"
    ),
    "DEC-GCP_AUDIT-0016": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0016",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #16)"
    ),
    "DEC-CISCO_ASA-0017": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0017",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #17)"
    ),
    "DEC-SURICATA_EVE-0018": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0018",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #18)"
    ),
    "DEC-POSTGRES_AUDIT-0019": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0019",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #19)"
    ),
    "DEC-NGINX_ACCESS-0020": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0020",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #20)"
    ),
    "DEC-APACHE_ERROR-0021": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0021",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #21)"
    ),
    "DEC-LINUX_AUTH-0022": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0022",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #22)"
    ),
    "DEC-WIN_EVENT_4624-0023": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0023",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #23)"
    ),
    "DEC-WIN_EVENT_4625-0024": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0024",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #24)"
    ),
    "DEC-AWS_CLOUDTRAIL-0025": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0025",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #25)"
    ),
    "DEC-GCP_AUDIT-0026": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0026",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #26)"
    ),
    "DEC-CISCO_ASA-0027": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0027",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #27)"
    ),
    "DEC-SURICATA_EVE-0028": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0028",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #28)"
    ),
    "DEC-POSTGRES_AUDIT-0029": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0029",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #29)"
    ),
    "DEC-NGINX_ACCESS-0030": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0030",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #30)"
    ),
    "DEC-APACHE_ERROR-0031": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0031",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #31)"
    ),
    "DEC-LINUX_AUTH-0032": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0032",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #32)"
    ),
    "DEC-WIN_EVENT_4624-0033": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0033",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #33)"
    ),
    "DEC-WIN_EVENT_4625-0034": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0034",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #34)"
    ),
    "DEC-AWS_CLOUDTRAIL-0035": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0035",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #35)"
    ),
    "DEC-GCP_AUDIT-0036": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0036",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #36)"
    ),
    "DEC-CISCO_ASA-0037": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0037",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #37)"
    ),
    "DEC-SURICATA_EVE-0038": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0038",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #38)"
    ),
    "DEC-POSTGRES_AUDIT-0039": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0039",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #39)"
    ),
    "DEC-NGINX_ACCESS-0040": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0040",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #40)"
    ),
    "DEC-APACHE_ERROR-0041": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0041",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #41)"
    ),
    "DEC-LINUX_AUTH-0042": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0042",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #42)"
    ),
    "DEC-WIN_EVENT_4624-0043": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0043",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #43)"
    ),
    "DEC-WIN_EVENT_4625-0044": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0044",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #44)"
    ),
    "DEC-AWS_CLOUDTRAIL-0045": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0045",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #45)"
    ),
    "DEC-GCP_AUDIT-0046": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0046",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #46)"
    ),
    "DEC-CISCO_ASA-0047": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0047",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #47)"
    ),
    "DEC-SURICATA_EVE-0048": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0048",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #48)"
    ),
    "DEC-POSTGRES_AUDIT-0049": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0049",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #49)"
    ),
    "DEC-NGINX_ACCESS-0050": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0050",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #50)"
    ),
    "DEC-APACHE_ERROR-0051": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0051",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #51)"
    ),
    "DEC-LINUX_AUTH-0052": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0052",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #52)"
    ),
    "DEC-WIN_EVENT_4624-0053": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0053",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #53)"
    ),
    "DEC-WIN_EVENT_4625-0054": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0054",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #54)"
    ),
    "DEC-AWS_CLOUDTRAIL-0055": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0055",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #55)"
    ),
    "DEC-GCP_AUDIT-0056": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0056",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #56)"
    ),
    "DEC-CISCO_ASA-0057": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0057",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #57)"
    ),
    "DEC-SURICATA_EVE-0058": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0058",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #58)"
    ),
    "DEC-POSTGRES_AUDIT-0059": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0059",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #59)"
    ),
    "DEC-NGINX_ACCESS-0060": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0060",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #60)"
    ),
    "DEC-APACHE_ERROR-0061": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0061",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #61)"
    ),
    "DEC-LINUX_AUTH-0062": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0062",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #62)"
    ),
    "DEC-WIN_EVENT_4624-0063": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0063",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #63)"
    ),
    "DEC-WIN_EVENT_4625-0064": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0064",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #64)"
    ),
    "DEC-AWS_CLOUDTRAIL-0065": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0065",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #65)"
    ),
    "DEC-GCP_AUDIT-0066": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0066",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #66)"
    ),
    "DEC-CISCO_ASA-0067": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0067",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #67)"
    ),
    "DEC-SURICATA_EVE-0068": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0068",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #68)"
    ),
    "DEC-POSTGRES_AUDIT-0069": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0069",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #69)"
    ),
    "DEC-NGINX_ACCESS-0070": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0070",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #70)"
    ),
    "DEC-APACHE_ERROR-0071": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0071",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #71)"
    ),
    "DEC-LINUX_AUTH-0072": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0072",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #72)"
    ),
    "DEC-WIN_EVENT_4624-0073": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0073",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #73)"
    ),
    "DEC-WIN_EVENT_4625-0074": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0074",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #74)"
    ),
    "DEC-AWS_CLOUDTRAIL-0075": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0075",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #75)"
    ),
    "DEC-GCP_AUDIT-0076": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0076",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #76)"
    ),
    "DEC-CISCO_ASA-0077": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0077",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #77)"
    ),
    "DEC-SURICATA_EVE-0078": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0078",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #78)"
    ),
    "DEC-POSTGRES_AUDIT-0079": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0079",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #79)"
    ),
    "DEC-NGINX_ACCESS-0080": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0080",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #80)"
    ),
    "DEC-APACHE_ERROR-0081": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0081",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #81)"
    ),
    "DEC-LINUX_AUTH-0082": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0082",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #82)"
    ),
    "DEC-WIN_EVENT_4624-0083": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0083",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #83)"
    ),
    "DEC-WIN_EVENT_4625-0084": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0084",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #84)"
    ),
    "DEC-AWS_CLOUDTRAIL-0085": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0085",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #85)"
    ),
    "DEC-GCP_AUDIT-0086": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0086",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #86)"
    ),
    "DEC-CISCO_ASA-0087": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0087",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #87)"
    ),
    "DEC-SURICATA_EVE-0088": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0088",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #88)"
    ),
    "DEC-POSTGRES_AUDIT-0089": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0089",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #89)"
    ),
    "DEC-NGINX_ACCESS-0090": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0090",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #90)"
    ),
    "DEC-APACHE_ERROR-0091": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0091",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #91)"
    ),
    "DEC-LINUX_AUTH-0092": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0092",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #92)"
    ),
    "DEC-WIN_EVENT_4624-0093": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0093",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #93)"
    ),
    "DEC-WIN_EVENT_4625-0094": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0094",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #94)"
    ),
    "DEC-AWS_CLOUDTRAIL-0095": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0095",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #95)"
    ),
    "DEC-GCP_AUDIT-0096": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0096",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #96)"
    ),
    "DEC-CISCO_ASA-0097": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0097",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #97)"
    ),
    "DEC-SURICATA_EVE-0098": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0098",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #98)"
    ),
    "DEC-POSTGRES_AUDIT-0099": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0099",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #99)"
    ),
    "DEC-NGINX_ACCESS-0100": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0100",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #100)"
    ),
    "DEC-APACHE_ERROR-0101": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0101",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #101)"
    ),
    "DEC-LINUX_AUTH-0102": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0102",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #102)"
    ),
    "DEC-WIN_EVENT_4624-0103": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0103",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #103)"
    ),
    "DEC-WIN_EVENT_4625-0104": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0104",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #104)"
    ),
    "DEC-AWS_CLOUDTRAIL-0105": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0105",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #105)"
    ),
    "DEC-GCP_AUDIT-0106": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0106",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #106)"
    ),
    "DEC-CISCO_ASA-0107": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0107",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #107)"
    ),
    "DEC-SURICATA_EVE-0108": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0108",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #108)"
    ),
    "DEC-POSTGRES_AUDIT-0109": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0109",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #109)"
    ),
    "DEC-NGINX_ACCESS-0110": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0110",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #110)"
    ),
    "DEC-APACHE_ERROR-0111": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0111",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #111)"
    ),
    "DEC-LINUX_AUTH-0112": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0112",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #112)"
    ),
    "DEC-WIN_EVENT_4624-0113": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0113",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #113)"
    ),
    "DEC-WIN_EVENT_4625-0114": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0114",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #114)"
    ),
    "DEC-AWS_CLOUDTRAIL-0115": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0115",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #115)"
    ),
    "DEC-GCP_AUDIT-0116": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0116",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #116)"
    ),
    "DEC-CISCO_ASA-0117": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0117",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #117)"
    ),
    "DEC-SURICATA_EVE-0118": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0118",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #118)"
    ),
    "DEC-POSTGRES_AUDIT-0119": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0119",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #119)"
    ),
    "DEC-NGINX_ACCESS-0120": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0120",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #120)"
    ),
    "DEC-APACHE_ERROR-0121": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0121",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #121)"
    ),
    "DEC-LINUX_AUTH-0122": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0122",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #122)"
    ),
    "DEC-WIN_EVENT_4624-0123": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0123",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #123)"
    ),
    "DEC-WIN_EVENT_4625-0124": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0124",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #124)"
    ),
    "DEC-AWS_CLOUDTRAIL-0125": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0125",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #125)"
    ),
    "DEC-GCP_AUDIT-0126": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0126",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #126)"
    ),
    "DEC-CISCO_ASA-0127": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0127",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #127)"
    ),
    "DEC-SURICATA_EVE-0128": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0128",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #128)"
    ),
    "DEC-POSTGRES_AUDIT-0129": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0129",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #129)"
    ),
    "DEC-NGINX_ACCESS-0130": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0130",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #130)"
    ),
    "DEC-APACHE_ERROR-0131": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0131",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #131)"
    ),
    "DEC-LINUX_AUTH-0132": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0132",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #132)"
    ),
    "DEC-WIN_EVENT_4624-0133": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0133",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #133)"
    ),
    "DEC-WIN_EVENT_4625-0134": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0134",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #134)"
    ),
    "DEC-AWS_CLOUDTRAIL-0135": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0135",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #135)"
    ),
    "DEC-GCP_AUDIT-0136": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0136",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #136)"
    ),
    "DEC-CISCO_ASA-0137": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0137",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #137)"
    ),
    "DEC-SURICATA_EVE-0138": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0138",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #138)"
    ),
    "DEC-POSTGRES_AUDIT-0139": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0139",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #139)"
    ),
    "DEC-NGINX_ACCESS-0140": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0140",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #140)"
    ),
    "DEC-APACHE_ERROR-0141": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0141",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #141)"
    ),
    "DEC-LINUX_AUTH-0142": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0142",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #142)"
    ),
    "DEC-WIN_EVENT_4624-0143": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0143",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #143)"
    ),
    "DEC-WIN_EVENT_4625-0144": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0144",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #144)"
    ),
    "DEC-AWS_CLOUDTRAIL-0145": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0145",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #145)"
    ),
    "DEC-GCP_AUDIT-0146": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0146",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #146)"
    ),
    "DEC-CISCO_ASA-0147": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0147",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #147)"
    ),
    "DEC-SURICATA_EVE-0148": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0148",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #148)"
    ),
    "DEC-POSTGRES_AUDIT-0149": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0149",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #149)"
    ),
    "DEC-NGINX_ACCESS-0150": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0150",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #150)"
    ),
    "DEC-APACHE_ERROR-0151": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0151",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #151)"
    ),
    "DEC-LINUX_AUTH-0152": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0152",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #152)"
    ),
    "DEC-WIN_EVENT_4624-0153": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0153",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #153)"
    ),
    "DEC-WIN_EVENT_4625-0154": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0154",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #154)"
    ),
    "DEC-AWS_CLOUDTRAIL-0155": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0155",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #155)"
    ),
    "DEC-GCP_AUDIT-0156": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0156",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #156)"
    ),
    "DEC-CISCO_ASA-0157": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0157",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #157)"
    ),
    "DEC-SURICATA_EVE-0158": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0158",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #158)"
    ),
    "DEC-POSTGRES_AUDIT-0159": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0159",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #159)"
    ),
    "DEC-NGINX_ACCESS-0160": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0160",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #160)"
    ),
    "DEC-APACHE_ERROR-0161": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0161",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #161)"
    ),
    "DEC-LINUX_AUTH-0162": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0162",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #162)"
    ),
    "DEC-WIN_EVENT_4624-0163": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0163",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #163)"
    ),
    "DEC-WIN_EVENT_4625-0164": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0164",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #164)"
    ),
    "DEC-AWS_CLOUDTRAIL-0165": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0165",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #165)"
    ),
    "DEC-GCP_AUDIT-0166": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0166",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #166)"
    ),
    "DEC-CISCO_ASA-0167": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0167",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #167)"
    ),
    "DEC-SURICATA_EVE-0168": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0168",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #168)"
    ),
    "DEC-POSTGRES_AUDIT-0169": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0169",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #169)"
    ),
    "DEC-NGINX_ACCESS-0170": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0170",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #170)"
    ),
    "DEC-APACHE_ERROR-0171": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0171",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #171)"
    ),
    "DEC-LINUX_AUTH-0172": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0172",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #172)"
    ),
    "DEC-WIN_EVENT_4624-0173": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0173",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #173)"
    ),
    "DEC-WIN_EVENT_4625-0174": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0174",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #174)"
    ),
    "DEC-AWS_CLOUDTRAIL-0175": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0175",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #175)"
    ),
    "DEC-GCP_AUDIT-0176": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0176",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #176)"
    ),
    "DEC-CISCO_ASA-0177": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0177",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #177)"
    ),
    "DEC-SURICATA_EVE-0178": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0178",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #178)"
    ),
    "DEC-POSTGRES_AUDIT-0179": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0179",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #179)"
    ),
    "DEC-NGINX_ACCESS-0180": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0180",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #180)"
    ),
    "DEC-APACHE_ERROR-0181": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0181",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #181)"
    ),
    "DEC-LINUX_AUTH-0182": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0182",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #182)"
    ),
    "DEC-WIN_EVENT_4624-0183": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0183",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #183)"
    ),
    "DEC-WIN_EVENT_4625-0184": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0184",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #184)"
    ),
    "DEC-AWS_CLOUDTRAIL-0185": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0185",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #185)"
    ),
    "DEC-GCP_AUDIT-0186": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0186",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #186)"
    ),
    "DEC-CISCO_ASA-0187": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0187",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #187)"
    ),
    "DEC-SURICATA_EVE-0188": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0188",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #188)"
    ),
    "DEC-POSTGRES_AUDIT-0189": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0189",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #189)"
    ),
    "DEC-NGINX_ACCESS-0190": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0190",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #190)"
    ),
    "DEC-APACHE_ERROR-0191": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0191",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #191)"
    ),
    "DEC-LINUX_AUTH-0192": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0192",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #192)"
    ),
    "DEC-WIN_EVENT_4624-0193": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0193",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #193)"
    ),
    "DEC-WIN_EVENT_4625-0194": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0194",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #194)"
    ),
    "DEC-AWS_CLOUDTRAIL-0195": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0195",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #195)"
    ),
    "DEC-GCP_AUDIT-0196": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0196",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #196)"
    ),
    "DEC-CISCO_ASA-0197": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0197",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #197)"
    ),
    "DEC-SURICATA_EVE-0198": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0198",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #198)"
    ),
    "DEC-POSTGRES_AUDIT-0199": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0199",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #199)"
    ),
    "DEC-NGINX_ACCESS-0200": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0200",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #200)"
    ),
    "DEC-APACHE_ERROR-0201": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0201",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #201)"
    ),
    "DEC-LINUX_AUTH-0202": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0202",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #202)"
    ),
    "DEC-WIN_EVENT_4624-0203": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0203",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #203)"
    ),
    "DEC-WIN_EVENT_4625-0204": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0204",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #204)"
    ),
    "DEC-AWS_CLOUDTRAIL-0205": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0205",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #205)"
    ),
    "DEC-GCP_AUDIT-0206": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0206",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #206)"
    ),
    "DEC-CISCO_ASA-0207": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0207",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #207)"
    ),
    "DEC-SURICATA_EVE-0208": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0208",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #208)"
    ),
    "DEC-POSTGRES_AUDIT-0209": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0209",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #209)"
    ),
    "DEC-NGINX_ACCESS-0210": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0210",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #210)"
    ),
    "DEC-APACHE_ERROR-0211": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0211",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #211)"
    ),
    "DEC-LINUX_AUTH-0212": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0212",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #212)"
    ),
    "DEC-WIN_EVENT_4624-0213": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0213",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #213)"
    ),
    "DEC-WIN_EVENT_4625-0214": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0214",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #214)"
    ),
    "DEC-AWS_CLOUDTRAIL-0215": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0215",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #215)"
    ),
    "DEC-GCP_AUDIT-0216": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0216",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #216)"
    ),
    "DEC-CISCO_ASA-0217": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0217",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #217)"
    ),
    "DEC-SURICATA_EVE-0218": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0218",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #218)"
    ),
    "DEC-POSTGRES_AUDIT-0219": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0219",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #219)"
    ),
    "DEC-NGINX_ACCESS-0220": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0220",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #220)"
    ),
    "DEC-APACHE_ERROR-0221": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0221",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #221)"
    ),
    "DEC-LINUX_AUTH-0222": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0222",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #222)"
    ),
    "DEC-WIN_EVENT_4624-0223": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0223",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #223)"
    ),
    "DEC-WIN_EVENT_4625-0224": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0224",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #224)"
    ),
    "DEC-AWS_CLOUDTRAIL-0225": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0225",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #225)"
    ),
    "DEC-GCP_AUDIT-0226": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0226",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #226)"
    ),
    "DEC-CISCO_ASA-0227": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0227",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #227)"
    ),
    "DEC-SURICATA_EVE-0228": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0228",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #228)"
    ),
    "DEC-POSTGRES_AUDIT-0229": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0229",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #229)"
    ),
    "DEC-NGINX_ACCESS-0230": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0230",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #230)"
    ),
    "DEC-APACHE_ERROR-0231": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0231",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #231)"
    ),
    "DEC-LINUX_AUTH-0232": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0232",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #232)"
    ),
    "DEC-WIN_EVENT_4624-0233": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0233",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #233)"
    ),
    "DEC-WIN_EVENT_4625-0234": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0234",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #234)"
    ),
    "DEC-AWS_CLOUDTRAIL-0235": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0235",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #235)"
    ),
    "DEC-GCP_AUDIT-0236": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0236",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #236)"
    ),
    "DEC-CISCO_ASA-0237": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0237",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #237)"
    ),
    "DEC-SURICATA_EVE-0238": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0238",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #238)"
    ),
    "DEC-POSTGRES_AUDIT-0239": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0239",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #239)"
    ),
    "DEC-NGINX_ACCESS-0240": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0240",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #240)"
    ),
    "DEC-APACHE_ERROR-0241": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0241",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #241)"
    ),
    "DEC-LINUX_AUTH-0242": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0242",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #242)"
    ),
    "DEC-WIN_EVENT_4624-0243": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0243",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #243)"
    ),
    "DEC-WIN_EVENT_4625-0244": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0244",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #244)"
    ),
    "DEC-AWS_CLOUDTRAIL-0245": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0245",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #245)"
    ),
    "DEC-GCP_AUDIT-0246": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0246",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #246)"
    ),
    "DEC-CISCO_ASA-0247": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0247",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #247)"
    ),
    "DEC-SURICATA_EVE-0248": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0248",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #248)"
    ),
    "DEC-POSTGRES_AUDIT-0249": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0249",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #249)"
    ),
    "DEC-NGINX_ACCESS-0250": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0250",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #250)"
    ),
    "DEC-APACHE_ERROR-0251": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0251",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #251)"
    ),
    "DEC-LINUX_AUTH-0252": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0252",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #252)"
    ),
    "DEC-WIN_EVENT_4624-0253": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0253",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #253)"
    ),
    "DEC-WIN_EVENT_4625-0254": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0254",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #254)"
    ),
    "DEC-AWS_CLOUDTRAIL-0255": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0255",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #255)"
    ),
    "DEC-GCP_AUDIT-0256": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0256",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #256)"
    ),
    "DEC-CISCO_ASA-0257": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0257",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #257)"
    ),
    "DEC-SURICATA_EVE-0258": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0258",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #258)"
    ),
    "DEC-POSTGRES_AUDIT-0259": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0259",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #259)"
    ),
    "DEC-NGINX_ACCESS-0260": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0260",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #260)"
    ),
    "DEC-APACHE_ERROR-0261": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0261",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #261)"
    ),
    "DEC-LINUX_AUTH-0262": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0262",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #262)"
    ),
    "DEC-WIN_EVENT_4624-0263": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0263",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #263)"
    ),
    "DEC-WIN_EVENT_4625-0264": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0264",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #264)"
    ),
    "DEC-AWS_CLOUDTRAIL-0265": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0265",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #265)"
    ),
    "DEC-GCP_AUDIT-0266": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0266",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #266)"
    ),
    "DEC-CISCO_ASA-0267": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0267",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #267)"
    ),
    "DEC-SURICATA_EVE-0268": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0268",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #268)"
    ),
    "DEC-POSTGRES_AUDIT-0269": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0269",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #269)"
    ),
    "DEC-NGINX_ACCESS-0270": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0270",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #270)"
    ),
    "DEC-APACHE_ERROR-0271": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0271",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #271)"
    ),
    "DEC-LINUX_AUTH-0272": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0272",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #272)"
    ),
    "DEC-WIN_EVENT_4624-0273": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0273",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #273)"
    ),
    "DEC-WIN_EVENT_4625-0274": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0274",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #274)"
    ),
    "DEC-AWS_CLOUDTRAIL-0275": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0275",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #275)"
    ),
    "DEC-GCP_AUDIT-0276": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0276",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #276)"
    ),
    "DEC-CISCO_ASA-0277": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0277",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #277)"
    ),
    "DEC-SURICATA_EVE-0278": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0278",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #278)"
    ),
    "DEC-POSTGRES_AUDIT-0279": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0279",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #279)"
    ),
    "DEC-NGINX_ACCESS-0280": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0280",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #280)"
    ),
    "DEC-APACHE_ERROR-0281": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0281",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #281)"
    ),
    "DEC-LINUX_AUTH-0282": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0282",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #282)"
    ),
    "DEC-WIN_EVENT_4624-0283": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0283",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #283)"
    ),
    "DEC-WIN_EVENT_4625-0284": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0284",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #284)"
    ),
    "DEC-AWS_CLOUDTRAIL-0285": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0285",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #285)"
    ),
    "DEC-GCP_AUDIT-0286": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0286",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #286)"
    ),
    "DEC-CISCO_ASA-0287": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0287",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #287)"
    ),
    "DEC-SURICATA_EVE-0288": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0288",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #288)"
    ),
    "DEC-POSTGRES_AUDIT-0289": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0289",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #289)"
    ),
    "DEC-NGINX_ACCESS-0290": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0290",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #290)"
    ),
    "DEC-APACHE_ERROR-0291": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0291",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #291)"
    ),
    "DEC-LINUX_AUTH-0292": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0292",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #292)"
    ),
    "DEC-WIN_EVENT_4624-0293": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0293",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #293)"
    ),
    "DEC-WIN_EVENT_4625-0294": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0294",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #294)"
    ),
    "DEC-AWS_CLOUDTRAIL-0295": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0295",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #295)"
    ),
    "DEC-GCP_AUDIT-0296": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0296",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #296)"
    ),
    "DEC-CISCO_ASA-0297": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0297",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #297)"
    ),
    "DEC-SURICATA_EVE-0298": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0298",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #298)"
    ),
    "DEC-POSTGRES_AUDIT-0299": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0299",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #299)"
    ),
    "DEC-NGINX_ACCESS-0300": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0300",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #300)"
    ),
    "DEC-APACHE_ERROR-0301": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0301",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #301)"
    ),
    "DEC-LINUX_AUTH-0302": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0302",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #302)"
    ),
    "DEC-WIN_EVENT_4624-0303": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0303",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #303)"
    ),
    "DEC-WIN_EVENT_4625-0304": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0304",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #304)"
    ),
    "DEC-AWS_CLOUDTRAIL-0305": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0305",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #305)"
    ),
    "DEC-GCP_AUDIT-0306": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0306",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #306)"
    ),
    "DEC-CISCO_ASA-0307": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0307",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #307)"
    ),
    "DEC-SURICATA_EVE-0308": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0308",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #308)"
    ),
    "DEC-POSTGRES_AUDIT-0309": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0309",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #309)"
    ),
    "DEC-NGINX_ACCESS-0310": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0310",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #310)"
    ),
    "DEC-APACHE_ERROR-0311": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0311",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #311)"
    ),
    "DEC-LINUX_AUTH-0312": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0312",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #312)"
    ),
    "DEC-WIN_EVENT_4624-0313": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0313",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #313)"
    ),
    "DEC-WIN_EVENT_4625-0314": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0314",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #314)"
    ),
    "DEC-AWS_CLOUDTRAIL-0315": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0315",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #315)"
    ),
    "DEC-GCP_AUDIT-0316": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0316",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #316)"
    ),
    "DEC-CISCO_ASA-0317": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0317",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #317)"
    ),
    "DEC-SURICATA_EVE-0318": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0318",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #318)"
    ),
    "DEC-POSTGRES_AUDIT-0319": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0319",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #319)"
    ),
    "DEC-NGINX_ACCESS-0320": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0320",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #320)"
    ),
    "DEC-APACHE_ERROR-0321": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0321",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #321)"
    ),
    "DEC-LINUX_AUTH-0322": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0322",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #322)"
    ),
    "DEC-WIN_EVENT_4624-0323": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0323",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #323)"
    ),
    "DEC-WIN_EVENT_4625-0324": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0324",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #324)"
    ),
    "DEC-AWS_CLOUDTRAIL-0325": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0325",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #325)"
    ),
    "DEC-GCP_AUDIT-0326": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0326",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #326)"
    ),
    "DEC-CISCO_ASA-0327": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0327",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #327)"
    ),
    "DEC-SURICATA_EVE-0328": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0328",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #328)"
    ),
    "DEC-POSTGRES_AUDIT-0329": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0329",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #329)"
    ),
    "DEC-NGINX_ACCESS-0330": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0330",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #330)"
    ),
    "DEC-APACHE_ERROR-0331": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0331",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #331)"
    ),
    "DEC-LINUX_AUTH-0332": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0332",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #332)"
    ),
    "DEC-WIN_EVENT_4624-0333": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0333",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #333)"
    ),
    "DEC-WIN_EVENT_4625-0334": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0334",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #334)"
    ),
    "DEC-AWS_CLOUDTRAIL-0335": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0335",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #335)"
    ),
    "DEC-GCP_AUDIT-0336": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0336",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #336)"
    ),
    "DEC-CISCO_ASA-0337": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0337",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #337)"
    ),
    "DEC-SURICATA_EVE-0338": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0338",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #338)"
    ),
    "DEC-POSTGRES_AUDIT-0339": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0339",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #339)"
    ),
    "DEC-NGINX_ACCESS-0340": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0340",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #340)"
    ),
    "DEC-APACHE_ERROR-0341": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0341",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #341)"
    ),
    "DEC-LINUX_AUTH-0342": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0342",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #342)"
    ),
    "DEC-WIN_EVENT_4624-0343": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0343",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #343)"
    ),
    "DEC-WIN_EVENT_4625-0344": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0344",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #344)"
    ),
    "DEC-AWS_CLOUDTRAIL-0345": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0345",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #345)"
    ),
    "DEC-GCP_AUDIT-0346": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0346",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #346)"
    ),
    "DEC-CISCO_ASA-0347": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0347",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #347)"
    ),
    "DEC-SURICATA_EVE-0348": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0348",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #348)"
    ),
    "DEC-POSTGRES_AUDIT-0349": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0349",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #349)"
    ),
    "DEC-NGINX_ACCESS-0350": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0350",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #350)"
    ),
    "DEC-APACHE_ERROR-0351": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0351",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #351)"
    ),
    "DEC-LINUX_AUTH-0352": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0352",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #352)"
    ),
    "DEC-WIN_EVENT_4624-0353": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0353",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #353)"
    ),
    "DEC-WIN_EVENT_4625-0354": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0354",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #354)"
    ),
    "DEC-AWS_CLOUDTRAIL-0355": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0355",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #355)"
    ),
    "DEC-GCP_AUDIT-0356": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0356",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #356)"
    ),
    "DEC-CISCO_ASA-0357": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0357",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #357)"
    ),
    "DEC-SURICATA_EVE-0358": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0358",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #358)"
    ),
    "DEC-POSTGRES_AUDIT-0359": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0359",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #359)"
    ),
    "DEC-NGINX_ACCESS-0360": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0360",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #360)"
    ),
    "DEC-APACHE_ERROR-0361": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0361",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #361)"
    ),
    "DEC-LINUX_AUTH-0362": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0362",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #362)"
    ),
    "DEC-WIN_EVENT_4624-0363": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0363",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #363)"
    ),
    "DEC-WIN_EVENT_4625-0364": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0364",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #364)"
    ),
    "DEC-AWS_CLOUDTRAIL-0365": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0365",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #365)"
    ),
    "DEC-GCP_AUDIT-0366": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0366",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #366)"
    ),
    "DEC-CISCO_ASA-0367": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0367",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #367)"
    ),
    "DEC-SURICATA_EVE-0368": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0368",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #368)"
    ),
    "DEC-POSTGRES_AUDIT-0369": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0369",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #369)"
    ),
    "DEC-NGINX_ACCESS-0370": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0370",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #370)"
    ),
    "DEC-APACHE_ERROR-0371": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0371",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #371)"
    ),
    "DEC-LINUX_AUTH-0372": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0372",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #372)"
    ),
    "DEC-WIN_EVENT_4624-0373": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0373",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #373)"
    ),
    "DEC-WIN_EVENT_4625-0374": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0374",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #374)"
    ),
    "DEC-AWS_CLOUDTRAIL-0375": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0375",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #375)"
    ),
    "DEC-GCP_AUDIT-0376": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0376",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #376)"
    ),
    "DEC-CISCO_ASA-0377": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0377",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #377)"
    ),
    "DEC-SURICATA_EVE-0378": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0378",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #378)"
    ),
    "DEC-POSTGRES_AUDIT-0379": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0379",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #379)"
    ),
    "DEC-NGINX_ACCESS-0380": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0380",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #380)"
    ),
    "DEC-APACHE_ERROR-0381": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0381",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #381)"
    ),
    "DEC-LINUX_AUTH-0382": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0382",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #382)"
    ),
    "DEC-WIN_EVENT_4624-0383": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0383",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #383)"
    ),
    "DEC-WIN_EVENT_4625-0384": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0384",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #384)"
    ),
    "DEC-AWS_CLOUDTRAIL-0385": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0385",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #385)"
    ),
    "DEC-GCP_AUDIT-0386": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0386",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #386)"
    ),
    "DEC-CISCO_ASA-0387": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0387",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #387)"
    ),
    "DEC-SURICATA_EVE-0388": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0388",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #388)"
    ),
    "DEC-POSTGRES_AUDIT-0389": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0389",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #389)"
    ),
    "DEC-NGINX_ACCESS-0390": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0390",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #390)"
    ),
    "DEC-APACHE_ERROR-0391": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0391",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #391)"
    ),
    "DEC-LINUX_AUTH-0392": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0392",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #392)"
    ),
    "DEC-WIN_EVENT_4624-0393": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0393",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #393)"
    ),
    "DEC-WIN_EVENT_4625-0394": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0394",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #394)"
    ),
    "DEC-AWS_CLOUDTRAIL-0395": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0395",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #395)"
    ),
    "DEC-GCP_AUDIT-0396": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0396",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #396)"
    ),
    "DEC-CISCO_ASA-0397": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0397",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #397)"
    ),
    "DEC-SURICATA_EVE-0398": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0398",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #398)"
    ),
    "DEC-POSTGRES_AUDIT-0399": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0399",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #399)"
    ),
    "DEC-NGINX_ACCESS-0400": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0400",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #400)"
    ),
    "DEC-APACHE_ERROR-0401": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0401",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #401)"
    ),
    "DEC-LINUX_AUTH-0402": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0402",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #402)"
    ),
    "DEC-WIN_EVENT_4624-0403": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0403",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #403)"
    ),
    "DEC-WIN_EVENT_4625-0404": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0404",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #404)"
    ),
    "DEC-AWS_CLOUDTRAIL-0405": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0405",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #405)"
    ),
    "DEC-GCP_AUDIT-0406": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0406",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #406)"
    ),
    "DEC-CISCO_ASA-0407": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0407",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #407)"
    ),
    "DEC-SURICATA_EVE-0408": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0408",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #408)"
    ),
    "DEC-POSTGRES_AUDIT-0409": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0409",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #409)"
    ),
    "DEC-NGINX_ACCESS-0410": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0410",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #410)"
    ),
    "DEC-APACHE_ERROR-0411": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0411",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #411)"
    ),
    "DEC-LINUX_AUTH-0412": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0412",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #412)"
    ),
    "DEC-WIN_EVENT_4624-0413": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0413",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #413)"
    ),
    "DEC-WIN_EVENT_4625-0414": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0414",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #414)"
    ),
    "DEC-AWS_CLOUDTRAIL-0415": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0415",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #415)"
    ),
    "DEC-GCP_AUDIT-0416": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0416",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #416)"
    ),
    "DEC-CISCO_ASA-0417": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0417",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #417)"
    ),
    "DEC-SURICATA_EVE-0418": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0418",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #418)"
    ),
    "DEC-POSTGRES_AUDIT-0419": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0419",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #419)"
    ),
    "DEC-NGINX_ACCESS-0420": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0420",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #420)"
    ),
    "DEC-APACHE_ERROR-0421": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0421",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #421)"
    ),
    "DEC-LINUX_AUTH-0422": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0422",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #422)"
    ),
    "DEC-WIN_EVENT_4624-0423": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0423",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #423)"
    ),
    "DEC-WIN_EVENT_4625-0424": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0424",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #424)"
    ),
    "DEC-AWS_CLOUDTRAIL-0425": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0425",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #425)"
    ),
    "DEC-GCP_AUDIT-0426": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0426",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #426)"
    ),
    "DEC-CISCO_ASA-0427": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0427",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #427)"
    ),
    "DEC-SURICATA_EVE-0428": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0428",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #428)"
    ),
    "DEC-POSTGRES_AUDIT-0429": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0429",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #429)"
    ),
    "DEC-NGINX_ACCESS-0430": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0430",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #430)"
    ),
    "DEC-APACHE_ERROR-0431": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0431",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #431)"
    ),
    "DEC-LINUX_AUTH-0432": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0432",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #432)"
    ),
    "DEC-WIN_EVENT_4624-0433": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0433",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #433)"
    ),
    "DEC-WIN_EVENT_4625-0434": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0434",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #434)"
    ),
    "DEC-AWS_CLOUDTRAIL-0435": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0435",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #435)"
    ),
    "DEC-GCP_AUDIT-0436": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0436",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #436)"
    ),
    "DEC-CISCO_ASA-0437": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0437",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #437)"
    ),
    "DEC-SURICATA_EVE-0438": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0438",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #438)"
    ),
    "DEC-POSTGRES_AUDIT-0439": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0439",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #439)"
    ),
    "DEC-NGINX_ACCESS-0440": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0440",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #440)"
    ),
    "DEC-APACHE_ERROR-0441": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0441",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #441)"
    ),
    "DEC-LINUX_AUTH-0442": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0442",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #442)"
    ),
    "DEC-WIN_EVENT_4624-0443": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0443",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #443)"
    ),
    "DEC-WIN_EVENT_4625-0444": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0444",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #444)"
    ),
    "DEC-AWS_CLOUDTRAIL-0445": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0445",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #445)"
    ),
    "DEC-GCP_AUDIT-0446": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0446",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #446)"
    ),
    "DEC-CISCO_ASA-0447": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0447",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #447)"
    ),
    "DEC-SURICATA_EVE-0448": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0448",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #448)"
    ),
    "DEC-POSTGRES_AUDIT-0449": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0449",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #449)"
    ),
    "DEC-NGINX_ACCESS-0450": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0450",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #450)"
    ),
    "DEC-APACHE_ERROR-0451": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0451",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #451)"
    ),
    "DEC-LINUX_AUTH-0452": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0452",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #452)"
    ),
    "DEC-WIN_EVENT_4624-0453": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0453",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #453)"
    ),
    "DEC-WIN_EVENT_4625-0454": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0454",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #454)"
    ),
    "DEC-AWS_CLOUDTRAIL-0455": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0455",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #455)"
    ),
    "DEC-GCP_AUDIT-0456": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0456",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #456)"
    ),
    "DEC-CISCO_ASA-0457": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0457",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #457)"
    ),
    "DEC-SURICATA_EVE-0458": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0458",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #458)"
    ),
    "DEC-POSTGRES_AUDIT-0459": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0459",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #459)"
    ),
    "DEC-NGINX_ACCESS-0460": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0460",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #460)"
    ),
    "DEC-APACHE_ERROR-0461": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0461",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #461)"
    ),
    "DEC-LINUX_AUTH-0462": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0462",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #462)"
    ),
    "DEC-WIN_EVENT_4624-0463": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0463",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #463)"
    ),
    "DEC-WIN_EVENT_4625-0464": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0464",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #464)"
    ),
    "DEC-AWS_CLOUDTRAIL-0465": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0465",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #465)"
    ),
    "DEC-GCP_AUDIT-0466": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0466",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #466)"
    ),
    "DEC-CISCO_ASA-0467": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0467",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #467)"
    ),
    "DEC-SURICATA_EVE-0468": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0468",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #468)"
    ),
    "DEC-POSTGRES_AUDIT-0469": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0469",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #469)"
    ),
    "DEC-NGINX_ACCESS-0470": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0470",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #470)"
    ),
    "DEC-APACHE_ERROR-0471": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0471",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #471)"
    ),
    "DEC-LINUX_AUTH-0472": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0472",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #472)"
    ),
    "DEC-WIN_EVENT_4624-0473": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0473",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #473)"
    ),
    "DEC-WIN_EVENT_4625-0474": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0474",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #474)"
    ),
    "DEC-AWS_CLOUDTRAIL-0475": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0475",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #475)"
    ),
    "DEC-GCP_AUDIT-0476": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0476",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #476)"
    ),
    "DEC-CISCO_ASA-0477": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0477",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #477)"
    ),
    "DEC-SURICATA_EVE-0478": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0478",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #478)"
    ),
    "DEC-POSTGRES_AUDIT-0479": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0479",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #479)"
    ),
    "DEC-NGINX_ACCESS-0480": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0480",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #480)"
    ),
    "DEC-APACHE_ERROR-0481": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0481",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #481)"
    ),
    "DEC-LINUX_AUTH-0482": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0482",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #482)"
    ),
    "DEC-WIN_EVENT_4624-0483": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0483",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #483)"
    ),
    "DEC-WIN_EVENT_4625-0484": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0484",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #484)"
    ),
    "DEC-AWS_CLOUDTRAIL-0485": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0485",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #485)"
    ),
    "DEC-GCP_AUDIT-0486": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0486",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #486)"
    ),
    "DEC-CISCO_ASA-0487": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0487",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #487)"
    ),
    "DEC-SURICATA_EVE-0488": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0488",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #488)"
    ),
    "DEC-POSTGRES_AUDIT-0489": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0489",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #489)"
    ),
    "DEC-NGINX_ACCESS-0490": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0490",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #490)"
    ),
    "DEC-APACHE_ERROR-0491": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0491",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #491)"
    ),
    "DEC-LINUX_AUTH-0492": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0492",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #492)"
    ),
    "DEC-WIN_EVENT_4624-0493": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0493",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #493)"
    ),
    "DEC-WIN_EVENT_4625-0494": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0494",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #494)"
    ),
    "DEC-AWS_CLOUDTRAIL-0495": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0495",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #495)"
    ),
    "DEC-GCP_AUDIT-0496": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0496",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #496)"
    ),
    "DEC-CISCO_ASA-0497": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0497",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #497)"
    ),
    "DEC-SURICATA_EVE-0498": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0498",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #498)"
    ),
    "DEC-POSTGRES_AUDIT-0499": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0499",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #499)"
    ),
    "DEC-NGINX_ACCESS-0500": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0500",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #500)"
    ),
    "DEC-APACHE_ERROR-0501": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0501",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #501)"
    ),
    "DEC-LINUX_AUTH-0502": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0502",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #502)"
    ),
    "DEC-WIN_EVENT_4624-0503": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0503",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #503)"
    ),
    "DEC-WIN_EVENT_4625-0504": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0504",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #504)"
    ),
    "DEC-AWS_CLOUDTRAIL-0505": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0505",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #505)"
    ),
    "DEC-GCP_AUDIT-0506": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0506",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #506)"
    ),
    "DEC-CISCO_ASA-0507": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0507",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #507)"
    ),
    "DEC-SURICATA_EVE-0508": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0508",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #508)"
    ),
    "DEC-POSTGRES_AUDIT-0509": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0509",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #509)"
    ),
    "DEC-NGINX_ACCESS-0510": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0510",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #510)"
    ),
    "DEC-APACHE_ERROR-0511": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0511",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #511)"
    ),
    "DEC-LINUX_AUTH-0512": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0512",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #512)"
    ),
    "DEC-WIN_EVENT_4624-0513": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0513",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #513)"
    ),
    "DEC-WIN_EVENT_4625-0514": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0514",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #514)"
    ),
    "DEC-AWS_CLOUDTRAIL-0515": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0515",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #515)"
    ),
    "DEC-GCP_AUDIT-0516": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0516",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #516)"
    ),
    "DEC-CISCO_ASA-0517": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0517",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #517)"
    ),
    "DEC-SURICATA_EVE-0518": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0518",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #518)"
    ),
    "DEC-POSTGRES_AUDIT-0519": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0519",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #519)"
    ),
    "DEC-NGINX_ACCESS-0520": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0520",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #520)"
    ),
    "DEC-APACHE_ERROR-0521": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0521",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #521)"
    ),
    "DEC-LINUX_AUTH-0522": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0522",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #522)"
    ),
    "DEC-WIN_EVENT_4624-0523": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0523",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #523)"
    ),
    "DEC-WIN_EVENT_4625-0524": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0524",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #524)"
    ),
    "DEC-AWS_CLOUDTRAIL-0525": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0525",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #525)"
    ),
    "DEC-GCP_AUDIT-0526": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0526",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #526)"
    ),
    "DEC-CISCO_ASA-0527": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0527",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #527)"
    ),
    "DEC-SURICATA_EVE-0528": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0528",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #528)"
    ),
    "DEC-POSTGRES_AUDIT-0529": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0529",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #529)"
    ),
    "DEC-NGINX_ACCESS-0530": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0530",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #530)"
    ),
    "DEC-APACHE_ERROR-0531": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0531",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #531)"
    ),
    "DEC-LINUX_AUTH-0532": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0532",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #532)"
    ),
    "DEC-WIN_EVENT_4624-0533": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0533",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #533)"
    ),
    "DEC-WIN_EVENT_4625-0534": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0534",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #534)"
    ),
    "DEC-AWS_CLOUDTRAIL-0535": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0535",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #535)"
    ),
    "DEC-GCP_AUDIT-0536": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0536",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #536)"
    ),
    "DEC-CISCO_ASA-0537": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0537",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #537)"
    ),
    "DEC-SURICATA_EVE-0538": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0538",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #538)"
    ),
    "DEC-POSTGRES_AUDIT-0539": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0539",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #539)"
    ),
    "DEC-NGINX_ACCESS-0540": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0540",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #540)"
    ),
    "DEC-APACHE_ERROR-0541": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0541",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #541)"
    ),
    "DEC-LINUX_AUTH-0542": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0542",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #542)"
    ),
    "DEC-WIN_EVENT_4624-0543": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0543",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #543)"
    ),
    "DEC-WIN_EVENT_4625-0544": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0544",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #544)"
    ),
    "DEC-AWS_CLOUDTRAIL-0545": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0545",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #545)"
    ),
    "DEC-GCP_AUDIT-0546": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0546",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #546)"
    ),
    "DEC-CISCO_ASA-0547": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0547",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #547)"
    ),
    "DEC-SURICATA_EVE-0548": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0548",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #548)"
    ),
    "DEC-POSTGRES_AUDIT-0549": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0549",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #549)"
    ),
    "DEC-NGINX_ACCESS-0550": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0550",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #550)"
    ),
    "DEC-APACHE_ERROR-0551": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0551",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #551)"
    ),
    "DEC-LINUX_AUTH-0552": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0552",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #552)"
    ),
    "DEC-WIN_EVENT_4624-0553": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0553",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #553)"
    ),
    "DEC-WIN_EVENT_4625-0554": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0554",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #554)"
    ),
    "DEC-AWS_CLOUDTRAIL-0555": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0555",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #555)"
    ),
    "DEC-GCP_AUDIT-0556": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0556",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #556)"
    ),
    "DEC-CISCO_ASA-0557": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0557",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #557)"
    ),
    "DEC-SURICATA_EVE-0558": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0558",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #558)"
    ),
    "DEC-POSTGRES_AUDIT-0559": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0559",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #559)"
    ),
    "DEC-NGINX_ACCESS-0560": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0560",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #560)"
    ),
    "DEC-APACHE_ERROR-0561": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0561",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #561)"
    ),
    "DEC-LINUX_AUTH-0562": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0562",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #562)"
    ),
    "DEC-WIN_EVENT_4624-0563": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0563",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #563)"
    ),
    "DEC-WIN_EVENT_4625-0564": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0564",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #564)"
    ),
    "DEC-AWS_CLOUDTRAIL-0565": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0565",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #565)"
    ),
    "DEC-GCP_AUDIT-0566": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0566",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #566)"
    ),
    "DEC-CISCO_ASA-0567": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0567",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #567)"
    ),
    "DEC-SURICATA_EVE-0568": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0568",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #568)"
    ),
    "DEC-POSTGRES_AUDIT-0569": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0569",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #569)"
    ),
    "DEC-NGINX_ACCESS-0570": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0570",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #570)"
    ),
    "DEC-APACHE_ERROR-0571": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0571",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #571)"
    ),
    "DEC-LINUX_AUTH-0572": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0572",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #572)"
    ),
    "DEC-WIN_EVENT_4624-0573": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0573",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #573)"
    ),
    "DEC-WIN_EVENT_4625-0574": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0574",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #574)"
    ),
    "DEC-AWS_CLOUDTRAIL-0575": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0575",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #575)"
    ),
    "DEC-GCP_AUDIT-0576": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0576",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #576)"
    ),
    "DEC-CISCO_ASA-0577": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0577",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #577)"
    ),
    "DEC-SURICATA_EVE-0578": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0578",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #578)"
    ),
    "DEC-POSTGRES_AUDIT-0579": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0579",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #579)"
    ),
    "DEC-NGINX_ACCESS-0580": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0580",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #580)"
    ),
    "DEC-APACHE_ERROR-0581": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0581",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #581)"
    ),
    "DEC-LINUX_AUTH-0582": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0582",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #582)"
    ),
    "DEC-WIN_EVENT_4624-0583": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0583",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #583)"
    ),
    "DEC-WIN_EVENT_4625-0584": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0584",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #584)"
    ),
    "DEC-AWS_CLOUDTRAIL-0585": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0585",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #585)"
    ),
    "DEC-GCP_AUDIT-0586": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0586",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #586)"
    ),
    "DEC-CISCO_ASA-0587": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0587",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #587)"
    ),
    "DEC-SURICATA_EVE-0588": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0588",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #588)"
    ),
    "DEC-POSTGRES_AUDIT-0589": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0589",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #589)"
    ),
    "DEC-NGINX_ACCESS-0590": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0590",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #590)"
    ),
    "DEC-APACHE_ERROR-0591": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0591",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #591)"
    ),
    "DEC-LINUX_AUTH-0592": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0592",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #592)"
    ),
    "DEC-WIN_EVENT_4624-0593": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0593",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #593)"
    ),
    "DEC-WIN_EVENT_4625-0594": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0594",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #594)"
    ),
    "DEC-AWS_CLOUDTRAIL-0595": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0595",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #595)"
    ),
    "DEC-GCP_AUDIT-0596": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0596",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #596)"
    ),
    "DEC-CISCO_ASA-0597": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0597",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #597)"
    ),
    "DEC-SURICATA_EVE-0598": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0598",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #598)"
    ),
    "DEC-POSTGRES_AUDIT-0599": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0599",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #599)"
    ),
    "DEC-NGINX_ACCESS-0600": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0600",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #600)"
    ),
    "DEC-APACHE_ERROR-0601": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0601",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #601)"
    ),
    "DEC-LINUX_AUTH-0602": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0602",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #602)"
    ),
    "DEC-WIN_EVENT_4624-0603": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0603",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #603)"
    ),
    "DEC-WIN_EVENT_4625-0604": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0604",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #604)"
    ),
    "DEC-AWS_CLOUDTRAIL-0605": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0605",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #605)"
    ),
    "DEC-GCP_AUDIT-0606": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0606",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #606)"
    ),
    "DEC-CISCO_ASA-0607": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0607",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #607)"
    ),
    "DEC-SURICATA_EVE-0608": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0608",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #608)"
    ),
    "DEC-POSTGRES_AUDIT-0609": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0609",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #609)"
    ),
    "DEC-NGINX_ACCESS-0610": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0610",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #610)"
    ),
    "DEC-APACHE_ERROR-0611": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0611",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #611)"
    ),
    "DEC-LINUX_AUTH-0612": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0612",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #612)"
    ),
    "DEC-WIN_EVENT_4624-0613": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0613",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #613)"
    ),
    "DEC-WIN_EVENT_4625-0614": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0614",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #614)"
    ),
    "DEC-AWS_CLOUDTRAIL-0615": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0615",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #615)"
    ),
    "DEC-GCP_AUDIT-0616": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0616",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #616)"
    ),
    "DEC-CISCO_ASA-0617": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0617",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #617)"
    ),
    "DEC-SURICATA_EVE-0618": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0618",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #618)"
    ),
    "DEC-POSTGRES_AUDIT-0619": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0619",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #619)"
    ),
    "DEC-NGINX_ACCESS-0620": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0620",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #620)"
    ),
    "DEC-APACHE_ERROR-0621": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0621",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #621)"
    ),
    "DEC-LINUX_AUTH-0622": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0622",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #622)"
    ),
    "DEC-WIN_EVENT_4624-0623": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0623",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #623)"
    ),
    "DEC-WIN_EVENT_4625-0624": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0624",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #624)"
    ),
    "DEC-AWS_CLOUDTRAIL-0625": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0625",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #625)"
    ),
    "DEC-GCP_AUDIT-0626": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0626",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #626)"
    ),
    "DEC-CISCO_ASA-0627": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0627",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #627)"
    ),
    "DEC-SURICATA_EVE-0628": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0628",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #628)"
    ),
    "DEC-POSTGRES_AUDIT-0629": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0629",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #629)"
    ),
    "DEC-NGINX_ACCESS-0630": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0630",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #630)"
    ),
    "DEC-APACHE_ERROR-0631": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0631",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #631)"
    ),
    "DEC-LINUX_AUTH-0632": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0632",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #632)"
    ),
    "DEC-WIN_EVENT_4624-0633": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0633",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #633)"
    ),
    "DEC-WIN_EVENT_4625-0634": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0634",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #634)"
    ),
    "DEC-AWS_CLOUDTRAIL-0635": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0635",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #635)"
    ),
    "DEC-GCP_AUDIT-0636": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0636",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #636)"
    ),
    "DEC-CISCO_ASA-0637": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0637",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #637)"
    ),
    "DEC-SURICATA_EVE-0638": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0638",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #638)"
    ),
    "DEC-POSTGRES_AUDIT-0639": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0639",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #639)"
    ),
    "DEC-NGINX_ACCESS-0640": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0640",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #640)"
    ),
    "DEC-APACHE_ERROR-0641": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0641",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #641)"
    ),
    "DEC-LINUX_AUTH-0642": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0642",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #642)"
    ),
    "DEC-WIN_EVENT_4624-0643": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0643",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #643)"
    ),
    "DEC-WIN_EVENT_4625-0644": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0644",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #644)"
    ),
    "DEC-AWS_CLOUDTRAIL-0645": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0645",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #645)"
    ),
    "DEC-GCP_AUDIT-0646": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0646",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #646)"
    ),
    "DEC-CISCO_ASA-0647": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0647",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #647)"
    ),
    "DEC-SURICATA_EVE-0648": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0648",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #648)"
    ),
    "DEC-POSTGRES_AUDIT-0649": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0649",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #649)"
    ),
    "DEC-NGINX_ACCESS-0650": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0650",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #650)"
    ),
    "DEC-APACHE_ERROR-0651": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0651",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #651)"
    ),
    "DEC-LINUX_AUTH-0652": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0652",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #652)"
    ),
    "DEC-WIN_EVENT_4624-0653": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0653",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #653)"
    ),
    "DEC-WIN_EVENT_4625-0654": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0654",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #654)"
    ),
    "DEC-AWS_CLOUDTRAIL-0655": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0655",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #655)"
    ),
    "DEC-GCP_AUDIT-0656": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0656",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #656)"
    ),
    "DEC-CISCO_ASA-0657": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0657",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #657)"
    ),
    "DEC-SURICATA_EVE-0658": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0658",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #658)"
    ),
    "DEC-POSTGRES_AUDIT-0659": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0659",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #659)"
    ),
    "DEC-NGINX_ACCESS-0660": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0660",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #660)"
    ),
    "DEC-APACHE_ERROR-0661": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0661",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #661)"
    ),
    "DEC-LINUX_AUTH-0662": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0662",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #662)"
    ),
    "DEC-WIN_EVENT_4624-0663": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0663",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #663)"
    ),
    "DEC-WIN_EVENT_4625-0664": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0664",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #664)"
    ),
    "DEC-AWS_CLOUDTRAIL-0665": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0665",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #665)"
    ),
    "DEC-GCP_AUDIT-0666": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0666",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #666)"
    ),
    "DEC-CISCO_ASA-0667": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0667",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #667)"
    ),
    "DEC-SURICATA_EVE-0668": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0668",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #668)"
    ),
    "DEC-POSTGRES_AUDIT-0669": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0669",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #669)"
    ),
    "DEC-NGINX_ACCESS-0670": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0670",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #670)"
    ),
    "DEC-APACHE_ERROR-0671": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0671",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #671)"
    ),
    "DEC-LINUX_AUTH-0672": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0672",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #672)"
    ),
    "DEC-WIN_EVENT_4624-0673": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0673",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #673)"
    ),
    "DEC-WIN_EVENT_4625-0674": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0674",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #674)"
    ),
    "DEC-AWS_CLOUDTRAIL-0675": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0675",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #675)"
    ),
    "DEC-GCP_AUDIT-0676": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0676",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #676)"
    ),
    "DEC-CISCO_ASA-0677": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0677",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #677)"
    ),
    "DEC-SURICATA_EVE-0678": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0678",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #678)"
    ),
    "DEC-POSTGRES_AUDIT-0679": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0679",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #679)"
    ),
    "DEC-NGINX_ACCESS-0680": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0680",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #680)"
    ),
    "DEC-APACHE_ERROR-0681": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0681",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #681)"
    ),
    "DEC-LINUX_AUTH-0682": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0682",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #682)"
    ),
    "DEC-WIN_EVENT_4624-0683": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0683",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #683)"
    ),
    "DEC-WIN_EVENT_4625-0684": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0684",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #684)"
    ),
    "DEC-AWS_CLOUDTRAIL-0685": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0685",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #685)"
    ),
    "DEC-GCP_AUDIT-0686": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0686",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #686)"
    ),
    "DEC-CISCO_ASA-0687": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0687",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #687)"
    ),
    "DEC-SURICATA_EVE-0688": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0688",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #688)"
    ),
    "DEC-POSTGRES_AUDIT-0689": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0689",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #689)"
    ),
    "DEC-NGINX_ACCESS-0690": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0690",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #690)"
    ),
    "DEC-APACHE_ERROR-0691": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0691",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #691)"
    ),
    "DEC-LINUX_AUTH-0692": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0692",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #692)"
    ),
    "DEC-WIN_EVENT_4624-0693": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0693",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #693)"
    ),
    "DEC-WIN_EVENT_4625-0694": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0694",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #694)"
    ),
    "DEC-AWS_CLOUDTRAIL-0695": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0695",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #695)"
    ),
    "DEC-GCP_AUDIT-0696": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0696",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #696)"
    ),
    "DEC-CISCO_ASA-0697": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0697",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #697)"
    ),
    "DEC-SURICATA_EVE-0698": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0698",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #698)"
    ),
    "DEC-POSTGRES_AUDIT-0699": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0699",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #699)"
    ),
    "DEC-NGINX_ACCESS-0700": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0700",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #700)"
    ),
    "DEC-APACHE_ERROR-0701": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0701",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #701)"
    ),
    "DEC-LINUX_AUTH-0702": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0702",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #702)"
    ),
    "DEC-WIN_EVENT_4624-0703": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0703",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #703)"
    ),
    "DEC-WIN_EVENT_4625-0704": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0704",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #704)"
    ),
    "DEC-AWS_CLOUDTRAIL-0705": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0705",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #705)"
    ),
    "DEC-GCP_AUDIT-0706": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0706",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #706)"
    ),
    "DEC-CISCO_ASA-0707": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0707",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #707)"
    ),
    "DEC-SURICATA_EVE-0708": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0708",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #708)"
    ),
    "DEC-POSTGRES_AUDIT-0709": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0709",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #709)"
    ),
    "DEC-NGINX_ACCESS-0710": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0710",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #710)"
    ),
    "DEC-APACHE_ERROR-0711": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0711",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #711)"
    ),
    "DEC-LINUX_AUTH-0712": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0712",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #712)"
    ),
    "DEC-WIN_EVENT_4624-0713": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0713",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #713)"
    ),
    "DEC-WIN_EVENT_4625-0714": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0714",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #714)"
    ),
    "DEC-AWS_CLOUDTRAIL-0715": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0715",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #715)"
    ),
    "DEC-GCP_AUDIT-0716": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0716",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #716)"
    ),
    "DEC-CISCO_ASA-0717": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0717",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #717)"
    ),
    "DEC-SURICATA_EVE-0718": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0718",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #718)"
    ),
    "DEC-POSTGRES_AUDIT-0719": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0719",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #719)"
    ),
    "DEC-NGINX_ACCESS-0720": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0720",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #720)"
    ),
    "DEC-APACHE_ERROR-0721": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0721",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #721)"
    ),
    "DEC-LINUX_AUTH-0722": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0722",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #722)"
    ),
    "DEC-WIN_EVENT_4624-0723": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0723",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #723)"
    ),
    "DEC-WIN_EVENT_4625-0724": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0724",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #724)"
    ),
    "DEC-AWS_CLOUDTRAIL-0725": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0725",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #725)"
    ),
    "DEC-GCP_AUDIT-0726": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0726",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #726)"
    ),
    "DEC-CISCO_ASA-0727": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0727",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #727)"
    ),
    "DEC-SURICATA_EVE-0728": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0728",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #728)"
    ),
    "DEC-POSTGRES_AUDIT-0729": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0729",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #729)"
    ),
    "DEC-NGINX_ACCESS-0730": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0730",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #730)"
    ),
    "DEC-APACHE_ERROR-0731": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0731",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #731)"
    ),
    "DEC-LINUX_AUTH-0732": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0732",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #732)"
    ),
    "DEC-WIN_EVENT_4624-0733": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0733",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #733)"
    ),
    "DEC-WIN_EVENT_4625-0734": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0734",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #734)"
    ),
    "DEC-AWS_CLOUDTRAIL-0735": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0735",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #735)"
    ),
    "DEC-GCP_AUDIT-0736": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0736",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #736)"
    ),
    "DEC-CISCO_ASA-0737": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0737",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #737)"
    ),
    "DEC-SURICATA_EVE-0738": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0738",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #738)"
    ),
    "DEC-POSTGRES_AUDIT-0739": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0739",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #739)"
    ),
    "DEC-NGINX_ACCESS-0740": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0740",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #740)"
    ),
    "DEC-APACHE_ERROR-0741": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0741",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #741)"
    ),
    "DEC-LINUX_AUTH-0742": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0742",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #742)"
    ),
    "DEC-WIN_EVENT_4624-0743": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0743",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #743)"
    ),
    "DEC-WIN_EVENT_4625-0744": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0744",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #744)"
    ),
    "DEC-AWS_CLOUDTRAIL-0745": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0745",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #745)"
    ),
    "DEC-GCP_AUDIT-0746": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0746",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #746)"
    ),
    "DEC-CISCO_ASA-0747": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0747",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #747)"
    ),
    "DEC-SURICATA_EVE-0748": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0748",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #748)"
    ),
    "DEC-POSTGRES_AUDIT-0749": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0749",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #749)"
    ),
    "DEC-NGINX_ACCESS-0750": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0750",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #750)"
    ),
    "DEC-APACHE_ERROR-0751": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0751",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #751)"
    ),
    "DEC-LINUX_AUTH-0752": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0752",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #752)"
    ),
    "DEC-WIN_EVENT_4624-0753": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0753",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #753)"
    ),
    "DEC-WIN_EVENT_4625-0754": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0754",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #754)"
    ),
    "DEC-AWS_CLOUDTRAIL-0755": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0755",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #755)"
    ),
    "DEC-GCP_AUDIT-0756": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0756",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #756)"
    ),
    "DEC-CISCO_ASA-0757": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0757",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #757)"
    ),
    "DEC-SURICATA_EVE-0758": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0758",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #758)"
    ),
    "DEC-POSTGRES_AUDIT-0759": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0759",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #759)"
    ),
    "DEC-NGINX_ACCESS-0760": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0760",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #760)"
    ),
    "DEC-APACHE_ERROR-0761": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0761",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #761)"
    ),
    "DEC-LINUX_AUTH-0762": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0762",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #762)"
    ),
    "DEC-WIN_EVENT_4624-0763": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0763",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #763)"
    ),
    "DEC-WIN_EVENT_4625-0764": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0764",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #764)"
    ),
    "DEC-AWS_CLOUDTRAIL-0765": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0765",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #765)"
    ),
    "DEC-GCP_AUDIT-0766": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0766",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #766)"
    ),
    "DEC-CISCO_ASA-0767": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0767",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #767)"
    ),
    "DEC-SURICATA_EVE-0768": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0768",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #768)"
    ),
    "DEC-POSTGRES_AUDIT-0769": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0769",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #769)"
    ),
    "DEC-NGINX_ACCESS-0770": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0770",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #770)"
    ),
    "DEC-APACHE_ERROR-0771": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0771",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #771)"
    ),
    "DEC-LINUX_AUTH-0772": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0772",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #772)"
    ),
    "DEC-WIN_EVENT_4624-0773": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0773",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #773)"
    ),
    "DEC-WIN_EVENT_4625-0774": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0774",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #774)"
    ),
    "DEC-AWS_CLOUDTRAIL-0775": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0775",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #775)"
    ),
    "DEC-GCP_AUDIT-0776": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0776",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #776)"
    ),
    "DEC-CISCO_ASA-0777": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0777",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #777)"
    ),
    "DEC-SURICATA_EVE-0778": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0778",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #778)"
    ),
    "DEC-POSTGRES_AUDIT-0779": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0779",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #779)"
    ),
    "DEC-NGINX_ACCESS-0780": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0780",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #780)"
    ),
    "DEC-APACHE_ERROR-0781": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0781",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #781)"
    ),
    "DEC-LINUX_AUTH-0782": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0782",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #782)"
    ),
    "DEC-WIN_EVENT_4624-0783": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0783",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #783)"
    ),
    "DEC-WIN_EVENT_4625-0784": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0784",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #784)"
    ),
    "DEC-AWS_CLOUDTRAIL-0785": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0785",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #785)"
    ),
    "DEC-GCP_AUDIT-0786": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0786",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #786)"
    ),
    "DEC-CISCO_ASA-0787": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0787",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #787)"
    ),
    "DEC-SURICATA_EVE-0788": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0788",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #788)"
    ),
    "DEC-POSTGRES_AUDIT-0789": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0789",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #789)"
    ),
    "DEC-NGINX_ACCESS-0790": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0790",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #790)"
    ),
    "DEC-APACHE_ERROR-0791": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0791",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #791)"
    ),
    "DEC-LINUX_AUTH-0792": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0792",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #792)"
    ),
    "DEC-WIN_EVENT_4624-0793": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0793",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #793)"
    ),
    "DEC-WIN_EVENT_4625-0794": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0794",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #794)"
    ),
    "DEC-AWS_CLOUDTRAIL-0795": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0795",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #795)"
    ),
    "DEC-GCP_AUDIT-0796": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0796",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #796)"
    ),
    "DEC-CISCO_ASA-0797": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0797",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #797)"
    ),
    "DEC-SURICATA_EVE-0798": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0798",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #798)"
    ),
    "DEC-POSTGRES_AUDIT-0799": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0799",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #799)"
    ),
    "DEC-NGINX_ACCESS-0800": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0800",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #800)"
    ),
    "DEC-APACHE_ERROR-0801": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0801",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #801)"
    ),
    "DEC-LINUX_AUTH-0802": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0802",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #802)"
    ),
    "DEC-WIN_EVENT_4624-0803": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0803",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #803)"
    ),
    "DEC-WIN_EVENT_4625-0804": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0804",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #804)"
    ),
    "DEC-AWS_CLOUDTRAIL-0805": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0805",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #805)"
    ),
    "DEC-GCP_AUDIT-0806": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0806",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #806)"
    ),
    "DEC-CISCO_ASA-0807": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0807",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #807)"
    ),
    "DEC-SURICATA_EVE-0808": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0808",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #808)"
    ),
    "DEC-POSTGRES_AUDIT-0809": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0809",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #809)"
    ),
    "DEC-NGINX_ACCESS-0810": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0810",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #810)"
    ),
    "DEC-APACHE_ERROR-0811": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0811",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #811)"
    ),
    "DEC-LINUX_AUTH-0812": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0812",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #812)"
    ),
    "DEC-WIN_EVENT_4624-0813": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0813",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #813)"
    ),
    "DEC-WIN_EVENT_4625-0814": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0814",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #814)"
    ),
    "DEC-AWS_CLOUDTRAIL-0815": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0815",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #815)"
    ),
    "DEC-GCP_AUDIT-0816": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0816",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #816)"
    ),
    "DEC-CISCO_ASA-0817": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0817",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #817)"
    ),
    "DEC-SURICATA_EVE-0818": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0818",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #818)"
    ),
    "DEC-POSTGRES_AUDIT-0819": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0819",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #819)"
    ),
    "DEC-NGINX_ACCESS-0820": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0820",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #820)"
    ),
    "DEC-APACHE_ERROR-0821": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0821",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #821)"
    ),
    "DEC-LINUX_AUTH-0822": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0822",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #822)"
    ),
    "DEC-WIN_EVENT_4624-0823": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0823",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #823)"
    ),
    "DEC-WIN_EVENT_4625-0824": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0824",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #824)"
    ),
    "DEC-AWS_CLOUDTRAIL-0825": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0825",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #825)"
    ),
    "DEC-GCP_AUDIT-0826": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0826",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #826)"
    ),
    "DEC-CISCO_ASA-0827": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0827",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #827)"
    ),
    "DEC-SURICATA_EVE-0828": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0828",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #828)"
    ),
    "DEC-POSTGRES_AUDIT-0829": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0829",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #829)"
    ),
    "DEC-NGINX_ACCESS-0830": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0830",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #830)"
    ),
    "DEC-APACHE_ERROR-0831": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0831",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #831)"
    ),
    "DEC-LINUX_AUTH-0832": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0832",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #832)"
    ),
    "DEC-WIN_EVENT_4624-0833": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0833",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #833)"
    ),
    "DEC-WIN_EVENT_4625-0834": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0834",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #834)"
    ),
    "DEC-AWS_CLOUDTRAIL-0835": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0835",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #835)"
    ),
    "DEC-GCP_AUDIT-0836": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0836",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #836)"
    ),
    "DEC-CISCO_ASA-0837": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0837",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #837)"
    ),
    "DEC-SURICATA_EVE-0838": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0838",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #838)"
    ),
    "DEC-POSTGRES_AUDIT-0839": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0839",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #839)"
    ),
    "DEC-NGINX_ACCESS-0840": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0840",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #840)"
    ),
    "DEC-APACHE_ERROR-0841": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0841",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #841)"
    ),
    "DEC-LINUX_AUTH-0842": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0842",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #842)"
    ),
    "DEC-WIN_EVENT_4624-0843": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0843",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #843)"
    ),
    "DEC-WIN_EVENT_4625-0844": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0844",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #844)"
    ),
    "DEC-AWS_CLOUDTRAIL-0845": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0845",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #845)"
    ),
    "DEC-GCP_AUDIT-0846": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0846",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #846)"
    ),
    "DEC-CISCO_ASA-0847": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0847",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #847)"
    ),
    "DEC-SURICATA_EVE-0848": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0848",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #848)"
    ),
    "DEC-POSTGRES_AUDIT-0849": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0849",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #849)"
    ),
    "DEC-NGINX_ACCESS-0850": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0850",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #850)"
    ),
    "DEC-APACHE_ERROR-0851": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0851",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #851)"
    ),
    "DEC-LINUX_AUTH-0852": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0852",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #852)"
    ),
    "DEC-WIN_EVENT_4624-0853": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0853",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #853)"
    ),
    "DEC-WIN_EVENT_4625-0854": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0854",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #854)"
    ),
    "DEC-AWS_CLOUDTRAIL-0855": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0855",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #855)"
    ),
    "DEC-GCP_AUDIT-0856": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0856",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #856)"
    ),
    "DEC-CISCO_ASA-0857": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0857",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #857)"
    ),
    "DEC-SURICATA_EVE-0858": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0858",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #858)"
    ),
    "DEC-POSTGRES_AUDIT-0859": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0859",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #859)"
    ),
    "DEC-NGINX_ACCESS-0860": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0860",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #860)"
    ),
    "DEC-APACHE_ERROR-0861": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0861",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #861)"
    ),
    "DEC-LINUX_AUTH-0862": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0862",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #862)"
    ),
    "DEC-WIN_EVENT_4624-0863": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0863",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #863)"
    ),
    "DEC-WIN_EVENT_4625-0864": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0864",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #864)"
    ),
    "DEC-AWS_CLOUDTRAIL-0865": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0865",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #865)"
    ),
    "DEC-GCP_AUDIT-0866": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0866",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #866)"
    ),
    "DEC-CISCO_ASA-0867": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0867",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #867)"
    ),
    "DEC-SURICATA_EVE-0868": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0868",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #868)"
    ),
    "DEC-POSTGRES_AUDIT-0869": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0869",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #869)"
    ),
    "DEC-NGINX_ACCESS-0870": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0870",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #870)"
    ),
    "DEC-APACHE_ERROR-0871": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0871",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #871)"
    ),
    "DEC-LINUX_AUTH-0872": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0872",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #872)"
    ),
    "DEC-WIN_EVENT_4624-0873": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0873",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #873)"
    ),
    "DEC-WIN_EVENT_4625-0874": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0874",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #874)"
    ),
    "DEC-AWS_CLOUDTRAIL-0875": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0875",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #875)"
    ),
    "DEC-GCP_AUDIT-0876": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0876",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #876)"
    ),
    "DEC-CISCO_ASA-0877": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0877",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #877)"
    ),
    "DEC-SURICATA_EVE-0878": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0878",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #878)"
    ),
    "DEC-POSTGRES_AUDIT-0879": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0879",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #879)"
    ),
    "DEC-NGINX_ACCESS-0880": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0880",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #880)"
    ),
    "DEC-APACHE_ERROR-0881": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0881",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #881)"
    ),
    "DEC-LINUX_AUTH-0882": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0882",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #882)"
    ),
    "DEC-WIN_EVENT_4624-0883": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0883",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #883)"
    ),
    "DEC-WIN_EVENT_4625-0884": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0884",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #884)"
    ),
    "DEC-AWS_CLOUDTRAIL-0885": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0885",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #885)"
    ),
    "DEC-GCP_AUDIT-0886": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0886",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #886)"
    ),
    "DEC-CISCO_ASA-0887": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0887",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #887)"
    ),
    "DEC-SURICATA_EVE-0888": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0888",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #888)"
    ),
    "DEC-POSTGRES_AUDIT-0889": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0889",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #889)"
    ),
    "DEC-NGINX_ACCESS-0890": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0890",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #890)"
    ),
    "DEC-APACHE_ERROR-0891": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0891",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #891)"
    ),
    "DEC-LINUX_AUTH-0892": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0892",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #892)"
    ),
    "DEC-WIN_EVENT_4624-0893": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0893",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #893)"
    ),
    "DEC-WIN_EVENT_4625-0894": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0894",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #894)"
    ),
    "DEC-AWS_CLOUDTRAIL-0895": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0895",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #895)"
    ),
    "DEC-GCP_AUDIT-0896": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0896",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #896)"
    ),
    "DEC-CISCO_ASA-0897": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0897",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #897)"
    ),
    "DEC-SURICATA_EVE-0898": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0898",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #898)"
    ),
    "DEC-POSTGRES_AUDIT-0899": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0899",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #899)"
    ),
    "DEC-NGINX_ACCESS-0900": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0900",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #900)"
    ),
    "DEC-APACHE_ERROR-0901": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0901",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #901)"
    ),
    "DEC-LINUX_AUTH-0902": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0902",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #902)"
    ),
    "DEC-WIN_EVENT_4624-0903": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0903",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #903)"
    ),
    "DEC-WIN_EVENT_4625-0904": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0904",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #904)"
    ),
    "DEC-AWS_CLOUDTRAIL-0905": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0905",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #905)"
    ),
    "DEC-GCP_AUDIT-0906": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0906",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #906)"
    ),
    "DEC-CISCO_ASA-0907": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0907",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #907)"
    ),
    "DEC-SURICATA_EVE-0908": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0908",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #908)"
    ),
    "DEC-POSTGRES_AUDIT-0909": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0909",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #909)"
    ),
    "DEC-NGINX_ACCESS-0910": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0910",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #910)"
    ),
    "DEC-APACHE_ERROR-0911": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0911",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #911)"
    ),
    "DEC-LINUX_AUTH-0912": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0912",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #912)"
    ),
    "DEC-WIN_EVENT_4624-0913": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0913",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #913)"
    ),
    "DEC-WIN_EVENT_4625-0914": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0914",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #914)"
    ),
    "DEC-AWS_CLOUDTRAIL-0915": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0915",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #915)"
    ),
    "DEC-GCP_AUDIT-0916": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0916",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #916)"
    ),
    "DEC-CISCO_ASA-0917": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0917",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #917)"
    ),
    "DEC-SURICATA_EVE-0918": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0918",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #918)"
    ),
    "DEC-POSTGRES_AUDIT-0919": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0919",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #919)"
    ),
    "DEC-NGINX_ACCESS-0920": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0920",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #920)"
    ),
    "DEC-APACHE_ERROR-0921": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0921",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #921)"
    ),
    "DEC-LINUX_AUTH-0922": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0922",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #922)"
    ),
    "DEC-WIN_EVENT_4624-0923": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0923",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #923)"
    ),
    "DEC-WIN_EVENT_4625-0924": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0924",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #924)"
    ),
    "DEC-AWS_CLOUDTRAIL-0925": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0925",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #925)"
    ),
    "DEC-GCP_AUDIT-0926": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0926",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #926)"
    ),
    "DEC-CISCO_ASA-0927": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0927",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #927)"
    ),
    "DEC-SURICATA_EVE-0928": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0928",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #928)"
    ),
    "DEC-POSTGRES_AUDIT-0929": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0929",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #929)"
    ),
    "DEC-NGINX_ACCESS-0930": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0930",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #930)"
    ),
    "DEC-APACHE_ERROR-0931": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0931",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #931)"
    ),
    "DEC-LINUX_AUTH-0932": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0932",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #932)"
    ),
    "DEC-WIN_EVENT_4624-0933": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0933",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #933)"
    ),
    "DEC-WIN_EVENT_4625-0934": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0934",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #934)"
    ),
    "DEC-AWS_CLOUDTRAIL-0935": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0935",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #935)"
    ),
    "DEC-GCP_AUDIT-0936": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0936",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #936)"
    ),
    "DEC-CISCO_ASA-0937": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0937",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #937)"
    ),
    "DEC-SURICATA_EVE-0938": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0938",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #938)"
    ),
    "DEC-POSTGRES_AUDIT-0939": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0939",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #939)"
    ),
    "DEC-NGINX_ACCESS-0940": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0940",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #940)"
    ),
    "DEC-APACHE_ERROR-0941": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0941",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #941)"
    ),
    "DEC-LINUX_AUTH-0942": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0942",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #942)"
    ),
    "DEC-WIN_EVENT_4624-0943": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0943",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #943)"
    ),
    "DEC-WIN_EVENT_4625-0944": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0944",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #944)"
    ),
    "DEC-AWS_CLOUDTRAIL-0945": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0945",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #945)"
    ),
    "DEC-GCP_AUDIT-0946": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0946",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #946)"
    ),
    "DEC-CISCO_ASA-0947": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0947",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #947)"
    ),
    "DEC-SURICATA_EVE-0948": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0948",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #948)"
    ),
    "DEC-POSTGRES_AUDIT-0949": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0949",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #949)"
    ),
    "DEC-NGINX_ACCESS-0950": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0950",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #950)"
    ),
    "DEC-APACHE_ERROR-0951": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0951",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #951)"
    ),
    "DEC-LINUX_AUTH-0952": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0952",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #952)"
    ),
    "DEC-WIN_EVENT_4624-0953": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0953",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #953)"
    ),
    "DEC-WIN_EVENT_4625-0954": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0954",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #954)"
    ),
    "DEC-AWS_CLOUDTRAIL-0955": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0955",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #955)"
    ),
    "DEC-GCP_AUDIT-0956": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0956",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #956)"
    ),
    "DEC-CISCO_ASA-0957": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0957",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #957)"
    ),
    "DEC-SURICATA_EVE-0958": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0958",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #958)"
    ),
    "DEC-POSTGRES_AUDIT-0959": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0959",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #959)"
    ),
    "DEC-NGINX_ACCESS-0960": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0960",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #960)"
    ),
    "DEC-APACHE_ERROR-0961": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0961",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #961)"
    ),
    "DEC-LINUX_AUTH-0962": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0962",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #962)"
    ),
    "DEC-WIN_EVENT_4624-0963": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0963",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #963)"
    ),
    "DEC-WIN_EVENT_4625-0964": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0964",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #964)"
    ),
    "DEC-AWS_CLOUDTRAIL-0965": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0965",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #965)"
    ),
    "DEC-GCP_AUDIT-0966": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0966",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #966)"
    ),
    "DEC-CISCO_ASA-0967": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0967",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #967)"
    ),
    "DEC-SURICATA_EVE-0968": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0968",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #968)"
    ),
    "DEC-POSTGRES_AUDIT-0969": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0969",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #969)"
    ),
    "DEC-NGINX_ACCESS-0970": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0970",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #970)"
    ),
    "DEC-APACHE_ERROR-0971": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0971",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #971)"
    ),
    "DEC-LINUX_AUTH-0972": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0972",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #972)"
    ),
    "DEC-WIN_EVENT_4624-0973": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0973",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #973)"
    ),
    "DEC-WIN_EVENT_4625-0974": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0974",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #974)"
    ),
    "DEC-AWS_CLOUDTRAIL-0975": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0975",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #975)"
    ),
    "DEC-GCP_AUDIT-0976": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0976",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #976)"
    ),
    "DEC-CISCO_ASA-0977": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0977",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #977)"
    ),
    "DEC-SURICATA_EVE-0978": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0978",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #978)"
    ),
    "DEC-POSTGRES_AUDIT-0979": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0979",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #979)"
    ),
    "DEC-NGINX_ACCESS-0980": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0980",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #980)"
    ),
    "DEC-APACHE_ERROR-0981": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0981",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #981)"
    ),
    "DEC-LINUX_AUTH-0982": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0982",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #982)"
    ),
    "DEC-WIN_EVENT_4624-0983": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0983",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #983)"
    ),
    "DEC-WIN_EVENT_4625-0984": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0984",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #984)"
    ),
    "DEC-AWS_CLOUDTRAIL-0985": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0985",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #985)"
    ),
    "DEC-GCP_AUDIT-0986": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0986",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #986)"
    ),
    "DEC-CISCO_ASA-0987": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0987",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #987)"
    ),
    "DEC-SURICATA_EVE-0988": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0988",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #988)"
    ),
    "DEC-POSTGRES_AUDIT-0989": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0989",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #989)"
    ),
    "DEC-NGINX_ACCESS-0990": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-0990",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #990)"
    ),
    "DEC-APACHE_ERROR-0991": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-0991",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #991)"
    ),
    "DEC-LINUX_AUTH-0992": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-0992",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #992)"
    ),
    "DEC-WIN_EVENT_4624-0993": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-0993",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #993)"
    ),
    "DEC-WIN_EVENT_4625-0994": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-0994",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #994)"
    ),
    "DEC-AWS_CLOUDTRAIL-0995": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-0995",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #995)"
    ),
    "DEC-GCP_AUDIT-0996": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-0996",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #996)"
    ),
    "DEC-CISCO_ASA-0997": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-0997",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #997)"
    ),
    "DEC-SURICATA_EVE-0998": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-0998",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #998)"
    ),
    "DEC-POSTGRES_AUDIT-0999": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-0999",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #999)"
    ),
    "DEC-NGINX_ACCESS-1000": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1000",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1000)"
    ),
    "DEC-APACHE_ERROR-1001": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1001",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1001)"
    ),
    "DEC-LINUX_AUTH-1002": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1002",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1002)"
    ),
    "DEC-WIN_EVENT_4624-1003": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1003",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1003)"
    ),
    "DEC-WIN_EVENT_4625-1004": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1004",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1004)"
    ),
    "DEC-AWS_CLOUDTRAIL-1005": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1005",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1005)"
    ),
    "DEC-GCP_AUDIT-1006": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1006",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1006)"
    ),
    "DEC-CISCO_ASA-1007": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1007",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1007)"
    ),
    "DEC-SURICATA_EVE-1008": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1008",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1008)"
    ),
    "DEC-POSTGRES_AUDIT-1009": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1009",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1009)"
    ),
    "DEC-NGINX_ACCESS-1010": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1010",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1010)"
    ),
    "DEC-APACHE_ERROR-1011": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1011",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1011)"
    ),
    "DEC-LINUX_AUTH-1012": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1012",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1012)"
    ),
    "DEC-WIN_EVENT_4624-1013": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1013",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1013)"
    ),
    "DEC-WIN_EVENT_4625-1014": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1014",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1014)"
    ),
    "DEC-AWS_CLOUDTRAIL-1015": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1015",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1015)"
    ),
    "DEC-GCP_AUDIT-1016": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1016",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1016)"
    ),
    "DEC-CISCO_ASA-1017": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1017",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1017)"
    ),
    "DEC-SURICATA_EVE-1018": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1018",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1018)"
    ),
    "DEC-POSTGRES_AUDIT-1019": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1019",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1019)"
    ),
    "DEC-NGINX_ACCESS-1020": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1020",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1020)"
    ),
    "DEC-APACHE_ERROR-1021": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1021",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1021)"
    ),
    "DEC-LINUX_AUTH-1022": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1022",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1022)"
    ),
    "DEC-WIN_EVENT_4624-1023": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1023",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1023)"
    ),
    "DEC-WIN_EVENT_4625-1024": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1024",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1024)"
    ),
    "DEC-AWS_CLOUDTRAIL-1025": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1025",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1025)"
    ),
    "DEC-GCP_AUDIT-1026": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1026",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1026)"
    ),
    "DEC-CISCO_ASA-1027": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1027",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1027)"
    ),
    "DEC-SURICATA_EVE-1028": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1028",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1028)"
    ),
    "DEC-POSTGRES_AUDIT-1029": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1029",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1029)"
    ),
    "DEC-NGINX_ACCESS-1030": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1030",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1030)"
    ),
    "DEC-APACHE_ERROR-1031": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1031",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1031)"
    ),
    "DEC-LINUX_AUTH-1032": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1032",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1032)"
    ),
    "DEC-WIN_EVENT_4624-1033": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1033",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1033)"
    ),
    "DEC-WIN_EVENT_4625-1034": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1034",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1034)"
    ),
    "DEC-AWS_CLOUDTRAIL-1035": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1035",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1035)"
    ),
    "DEC-GCP_AUDIT-1036": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1036",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1036)"
    ),
    "DEC-CISCO_ASA-1037": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1037",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1037)"
    ),
    "DEC-SURICATA_EVE-1038": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1038",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1038)"
    ),
    "DEC-POSTGRES_AUDIT-1039": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1039",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1039)"
    ),
    "DEC-NGINX_ACCESS-1040": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1040",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1040)"
    ),
    "DEC-APACHE_ERROR-1041": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1041",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1041)"
    ),
    "DEC-LINUX_AUTH-1042": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1042",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1042)"
    ),
    "DEC-WIN_EVENT_4624-1043": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1043",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1043)"
    ),
    "DEC-WIN_EVENT_4625-1044": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1044",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1044)"
    ),
    "DEC-AWS_CLOUDTRAIL-1045": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1045",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1045)"
    ),
    "DEC-GCP_AUDIT-1046": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1046",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1046)"
    ),
    "DEC-CISCO_ASA-1047": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1047",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1047)"
    ),
    "DEC-SURICATA_EVE-1048": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1048",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1048)"
    ),
    "DEC-POSTGRES_AUDIT-1049": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1049",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1049)"
    ),
    "DEC-NGINX_ACCESS-1050": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1050",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1050)"
    ),
    "DEC-APACHE_ERROR-1051": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1051",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1051)"
    ),
    "DEC-LINUX_AUTH-1052": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1052",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1052)"
    ),
    "DEC-WIN_EVENT_4624-1053": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1053",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1053)"
    ),
    "DEC-WIN_EVENT_4625-1054": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1054",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1054)"
    ),
    "DEC-AWS_CLOUDTRAIL-1055": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1055",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1055)"
    ),
    "DEC-GCP_AUDIT-1056": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1056",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1056)"
    ),
    "DEC-CISCO_ASA-1057": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1057",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1057)"
    ),
    "DEC-SURICATA_EVE-1058": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1058",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1058)"
    ),
    "DEC-POSTGRES_AUDIT-1059": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1059",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1059)"
    ),
    "DEC-NGINX_ACCESS-1060": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1060",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1060)"
    ),
    "DEC-APACHE_ERROR-1061": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1061",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1061)"
    ),
    "DEC-LINUX_AUTH-1062": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1062",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1062)"
    ),
    "DEC-WIN_EVENT_4624-1063": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1063",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1063)"
    ),
    "DEC-WIN_EVENT_4625-1064": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1064",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1064)"
    ),
    "DEC-AWS_CLOUDTRAIL-1065": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1065",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1065)"
    ),
    "DEC-GCP_AUDIT-1066": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1066",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1066)"
    ),
    "DEC-CISCO_ASA-1067": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1067",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1067)"
    ),
    "DEC-SURICATA_EVE-1068": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1068",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1068)"
    ),
    "DEC-POSTGRES_AUDIT-1069": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1069",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1069)"
    ),
    "DEC-NGINX_ACCESS-1070": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1070",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1070)"
    ),
    "DEC-APACHE_ERROR-1071": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1071",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1071)"
    ),
    "DEC-LINUX_AUTH-1072": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1072",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1072)"
    ),
    "DEC-WIN_EVENT_4624-1073": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1073",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1073)"
    ),
    "DEC-WIN_EVENT_4625-1074": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1074",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1074)"
    ),
    "DEC-AWS_CLOUDTRAIL-1075": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1075",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1075)"
    ),
    "DEC-GCP_AUDIT-1076": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1076",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1076)"
    ),
    "DEC-CISCO_ASA-1077": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1077",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1077)"
    ),
    "DEC-SURICATA_EVE-1078": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1078",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1078)"
    ),
    "DEC-POSTGRES_AUDIT-1079": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1079",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1079)"
    ),
    "DEC-NGINX_ACCESS-1080": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1080",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1080)"
    ),
    "DEC-APACHE_ERROR-1081": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1081",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1081)"
    ),
    "DEC-LINUX_AUTH-1082": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1082",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1082)"
    ),
    "DEC-WIN_EVENT_4624-1083": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1083",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1083)"
    ),
    "DEC-WIN_EVENT_4625-1084": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1084",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1084)"
    ),
    "DEC-AWS_CLOUDTRAIL-1085": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1085",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1085)"
    ),
    "DEC-GCP_AUDIT-1086": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1086",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1086)"
    ),
    "DEC-CISCO_ASA-1087": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1087",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1087)"
    ),
    "DEC-SURICATA_EVE-1088": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1088",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1088)"
    ),
    "DEC-POSTGRES_AUDIT-1089": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1089",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1089)"
    ),
    "DEC-NGINX_ACCESS-1090": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1090",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1090)"
    ),
    "DEC-APACHE_ERROR-1091": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1091",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1091)"
    ),
    "DEC-LINUX_AUTH-1092": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1092",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1092)"
    ),
    "DEC-WIN_EVENT_4624-1093": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1093",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1093)"
    ),
    "DEC-WIN_EVENT_4625-1094": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1094",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1094)"
    ),
    "DEC-AWS_CLOUDTRAIL-1095": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1095",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1095)"
    ),
    "DEC-GCP_AUDIT-1096": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1096",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1096)"
    ),
    "DEC-CISCO_ASA-1097": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1097",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1097)"
    ),
    "DEC-SURICATA_EVE-1098": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1098",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1098)"
    ),
    "DEC-POSTGRES_AUDIT-1099": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1099",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1099)"
    ),
    "DEC-NGINX_ACCESS-1100": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1100",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1100)"
    ),
    "DEC-APACHE_ERROR-1101": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1101",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1101)"
    ),
    "DEC-LINUX_AUTH-1102": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1102",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1102)"
    ),
    "DEC-WIN_EVENT_4624-1103": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1103",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1103)"
    ),
    "DEC-WIN_EVENT_4625-1104": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1104",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1104)"
    ),
    "DEC-AWS_CLOUDTRAIL-1105": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1105",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1105)"
    ),
    "DEC-GCP_AUDIT-1106": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1106",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1106)"
    ),
    "DEC-CISCO_ASA-1107": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1107",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1107)"
    ),
    "DEC-SURICATA_EVE-1108": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1108",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1108)"
    ),
    "DEC-POSTGRES_AUDIT-1109": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1109",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1109)"
    ),
    "DEC-NGINX_ACCESS-1110": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1110",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1110)"
    ),
    "DEC-APACHE_ERROR-1111": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1111",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1111)"
    ),
    "DEC-LINUX_AUTH-1112": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1112",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1112)"
    ),
    "DEC-WIN_EVENT_4624-1113": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1113",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1113)"
    ),
    "DEC-WIN_EVENT_4625-1114": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1114",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1114)"
    ),
    "DEC-AWS_CLOUDTRAIL-1115": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1115",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1115)"
    ),
    "DEC-GCP_AUDIT-1116": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1116",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1116)"
    ),
    "DEC-CISCO_ASA-1117": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1117",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1117)"
    ),
    "DEC-SURICATA_EVE-1118": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1118",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1118)"
    ),
    "DEC-POSTGRES_AUDIT-1119": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1119",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1119)"
    ),
    "DEC-NGINX_ACCESS-1120": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1120",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1120)"
    ),
    "DEC-APACHE_ERROR-1121": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1121",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1121)"
    ),
    "DEC-LINUX_AUTH-1122": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1122",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1122)"
    ),
    "DEC-WIN_EVENT_4624-1123": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1123",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1123)"
    ),
    "DEC-WIN_EVENT_4625-1124": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1124",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1124)"
    ),
    "DEC-AWS_CLOUDTRAIL-1125": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1125",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1125)"
    ),
    "DEC-GCP_AUDIT-1126": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1126",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1126)"
    ),
    "DEC-CISCO_ASA-1127": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1127",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1127)"
    ),
    "DEC-SURICATA_EVE-1128": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1128",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1128)"
    ),
    "DEC-POSTGRES_AUDIT-1129": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1129",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1129)"
    ),
    "DEC-NGINX_ACCESS-1130": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1130",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1130)"
    ),
    "DEC-APACHE_ERROR-1131": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1131",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1131)"
    ),
    "DEC-LINUX_AUTH-1132": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1132",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1132)"
    ),
    "DEC-WIN_EVENT_4624-1133": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1133",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1133)"
    ),
    "DEC-WIN_EVENT_4625-1134": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1134",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1134)"
    ),
    "DEC-AWS_CLOUDTRAIL-1135": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1135",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1135)"
    ),
    "DEC-GCP_AUDIT-1136": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1136",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1136)"
    ),
    "DEC-CISCO_ASA-1137": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1137",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1137)"
    ),
    "DEC-SURICATA_EVE-1138": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1138",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1138)"
    ),
    "DEC-POSTGRES_AUDIT-1139": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1139",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1139)"
    ),
    "DEC-NGINX_ACCESS-1140": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1140",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1140)"
    ),
    "DEC-APACHE_ERROR-1141": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1141",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1141)"
    ),
    "DEC-LINUX_AUTH-1142": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1142",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1142)"
    ),
    "DEC-WIN_EVENT_4624-1143": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1143",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1143)"
    ),
    "DEC-WIN_EVENT_4625-1144": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1144",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1144)"
    ),
    "DEC-AWS_CLOUDTRAIL-1145": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1145",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1145)"
    ),
    "DEC-GCP_AUDIT-1146": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1146",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1146)"
    ),
    "DEC-CISCO_ASA-1147": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1147",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1147)"
    ),
    "DEC-SURICATA_EVE-1148": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1148",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1148)"
    ),
    "DEC-POSTGRES_AUDIT-1149": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1149",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1149)"
    ),
    "DEC-NGINX_ACCESS-1150": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1150",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1150)"
    ),
    "DEC-APACHE_ERROR-1151": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1151",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1151)"
    ),
    "DEC-LINUX_AUTH-1152": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1152",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1152)"
    ),
    "DEC-WIN_EVENT_4624-1153": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1153",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1153)"
    ),
    "DEC-WIN_EVENT_4625-1154": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1154",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1154)"
    ),
    "DEC-AWS_CLOUDTRAIL-1155": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1155",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1155)"
    ),
    "DEC-GCP_AUDIT-1156": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1156",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1156)"
    ),
    "DEC-CISCO_ASA-1157": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1157",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1157)"
    ),
    "DEC-SURICATA_EVE-1158": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1158",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1158)"
    ),
    "DEC-POSTGRES_AUDIT-1159": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1159",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1159)"
    ),
    "DEC-NGINX_ACCESS-1160": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1160",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1160)"
    ),
    "DEC-APACHE_ERROR-1161": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1161",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1161)"
    ),
    "DEC-LINUX_AUTH-1162": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1162",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1162)"
    ),
    "DEC-WIN_EVENT_4624-1163": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1163",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1163)"
    ),
    "DEC-WIN_EVENT_4625-1164": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1164",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1164)"
    ),
    "DEC-AWS_CLOUDTRAIL-1165": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1165",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1165)"
    ),
    "DEC-GCP_AUDIT-1166": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1166",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1166)"
    ),
    "DEC-CISCO_ASA-1167": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1167",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1167)"
    ),
    "DEC-SURICATA_EVE-1168": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1168",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1168)"
    ),
    "DEC-POSTGRES_AUDIT-1169": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1169",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1169)"
    ),
    "DEC-NGINX_ACCESS-1170": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1170",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1170)"
    ),
    "DEC-APACHE_ERROR-1171": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1171",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1171)"
    ),
    "DEC-LINUX_AUTH-1172": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1172",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1172)"
    ),
    "DEC-WIN_EVENT_4624-1173": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1173",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1173)"
    ),
    "DEC-WIN_EVENT_4625-1174": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1174",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1174)"
    ),
    "DEC-AWS_CLOUDTRAIL-1175": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1175",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1175)"
    ),
    "DEC-GCP_AUDIT-1176": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1176",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1176)"
    ),
    "DEC-CISCO_ASA-1177": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1177",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1177)"
    ),
    "DEC-SURICATA_EVE-1178": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1178",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1178)"
    ),
    "DEC-POSTGRES_AUDIT-1179": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1179",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1179)"
    ),
    "DEC-NGINX_ACCESS-1180": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1180",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1180)"
    ),
    "DEC-APACHE_ERROR-1181": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1181",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1181)"
    ),
    "DEC-LINUX_AUTH-1182": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1182",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1182)"
    ),
    "DEC-WIN_EVENT_4624-1183": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1183",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1183)"
    ),
    "DEC-WIN_EVENT_4625-1184": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1184",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1184)"
    ),
    "DEC-AWS_CLOUDTRAIL-1185": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1185",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1185)"
    ),
    "DEC-GCP_AUDIT-1186": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1186",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1186)"
    ),
    "DEC-CISCO_ASA-1187": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1187",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1187)"
    ),
    "DEC-SURICATA_EVE-1188": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1188",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1188)"
    ),
    "DEC-POSTGRES_AUDIT-1189": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1189",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1189)"
    ),
    "DEC-NGINX_ACCESS-1190": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1190",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1190)"
    ),
    "DEC-APACHE_ERROR-1191": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1191",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1191)"
    ),
    "DEC-LINUX_AUTH-1192": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1192",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1192)"
    ),
    "DEC-WIN_EVENT_4624-1193": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1193",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1193)"
    ),
    "DEC-WIN_EVENT_4625-1194": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1194",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1194)"
    ),
    "DEC-AWS_CLOUDTRAIL-1195": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1195",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1195)"
    ),
    "DEC-GCP_AUDIT-1196": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1196",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1196)"
    ),
    "DEC-CISCO_ASA-1197": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1197",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1197)"
    ),
    "DEC-SURICATA_EVE-1198": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1198",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1198)"
    ),
    "DEC-POSTGRES_AUDIT-1199": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1199",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1199)"
    ),
    "DEC-NGINX_ACCESS-1200": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1200",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1200)"
    ),
    "DEC-APACHE_ERROR-1201": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1201",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1201)"
    ),
    "DEC-LINUX_AUTH-1202": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1202",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1202)"
    ),
    "DEC-WIN_EVENT_4624-1203": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1203",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1203)"
    ),
    "DEC-WIN_EVENT_4625-1204": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1204",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1204)"
    ),
    "DEC-AWS_CLOUDTRAIL-1205": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1205",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1205)"
    ),
    "DEC-GCP_AUDIT-1206": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1206",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1206)"
    ),
    "DEC-CISCO_ASA-1207": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1207",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1207)"
    ),
    "DEC-SURICATA_EVE-1208": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1208",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1208)"
    ),
    "DEC-POSTGRES_AUDIT-1209": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1209",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1209)"
    ),
    "DEC-NGINX_ACCESS-1210": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1210",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1210)"
    ),
    "DEC-APACHE_ERROR-1211": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1211",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1211)"
    ),
    "DEC-LINUX_AUTH-1212": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1212",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1212)"
    ),
    "DEC-WIN_EVENT_4624-1213": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1213",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1213)"
    ),
    "DEC-WIN_EVENT_4625-1214": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1214",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1214)"
    ),
    "DEC-AWS_CLOUDTRAIL-1215": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1215",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1215)"
    ),
    "DEC-GCP_AUDIT-1216": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1216",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1216)"
    ),
    "DEC-CISCO_ASA-1217": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1217",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1217)"
    ),
    "DEC-SURICATA_EVE-1218": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1218",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1218)"
    ),
    "DEC-POSTGRES_AUDIT-1219": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1219",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1219)"
    ),
    "DEC-NGINX_ACCESS-1220": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1220",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1220)"
    ),
    "DEC-APACHE_ERROR-1221": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1221",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1221)"
    ),
    "DEC-LINUX_AUTH-1222": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1222",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1222)"
    ),
    "DEC-WIN_EVENT_4624-1223": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1223",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1223)"
    ),
    "DEC-WIN_EVENT_4625-1224": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1224",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1224)"
    ),
    "DEC-AWS_CLOUDTRAIL-1225": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1225",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1225)"
    ),
    "DEC-GCP_AUDIT-1226": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1226",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1226)"
    ),
    "DEC-CISCO_ASA-1227": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1227",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1227)"
    ),
    "DEC-SURICATA_EVE-1228": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1228",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1228)"
    ),
    "DEC-POSTGRES_AUDIT-1229": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1229",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1229)"
    ),
    "DEC-NGINX_ACCESS-1230": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1230",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1230)"
    ),
    "DEC-APACHE_ERROR-1231": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1231",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1231)"
    ),
    "DEC-LINUX_AUTH-1232": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1232",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1232)"
    ),
    "DEC-WIN_EVENT_4624-1233": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1233",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1233)"
    ),
    "DEC-WIN_EVENT_4625-1234": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1234",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1234)"
    ),
    "DEC-AWS_CLOUDTRAIL-1235": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1235",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1235)"
    ),
    "DEC-GCP_AUDIT-1236": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1236",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1236)"
    ),
    "DEC-CISCO_ASA-1237": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1237",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1237)"
    ),
    "DEC-SURICATA_EVE-1238": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1238",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1238)"
    ),
    "DEC-POSTGRES_AUDIT-1239": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1239",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1239)"
    ),
    "DEC-NGINX_ACCESS-1240": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1240",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1240)"
    ),
    "DEC-APACHE_ERROR-1241": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1241",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1241)"
    ),
    "DEC-LINUX_AUTH-1242": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1242",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1242)"
    ),
    "DEC-WIN_EVENT_4624-1243": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1243",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1243)"
    ),
    "DEC-WIN_EVENT_4625-1244": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1244",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1244)"
    ),
    "DEC-AWS_CLOUDTRAIL-1245": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1245",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1245)"
    ),
    "DEC-GCP_AUDIT-1246": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1246",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1246)"
    ),
    "DEC-CISCO_ASA-1247": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1247",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1247)"
    ),
    "DEC-SURICATA_EVE-1248": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1248",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1248)"
    ),
    "DEC-POSTGRES_AUDIT-1249": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1249",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1249)"
    ),
    "DEC-NGINX_ACCESS-1250": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1250",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1250)"
    ),
    "DEC-APACHE_ERROR-1251": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1251",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1251)"
    ),
    "DEC-LINUX_AUTH-1252": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1252",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1252)"
    ),
    "DEC-WIN_EVENT_4624-1253": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1253",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1253)"
    ),
    "DEC-WIN_EVENT_4625-1254": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1254",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1254)"
    ),
    "DEC-AWS_CLOUDTRAIL-1255": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1255",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1255)"
    ),
    "DEC-GCP_AUDIT-1256": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1256",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1256)"
    ),
    "DEC-CISCO_ASA-1257": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1257",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1257)"
    ),
    "DEC-SURICATA_EVE-1258": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1258",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1258)"
    ),
    "DEC-POSTGRES_AUDIT-1259": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1259",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1259)"
    ),
    "DEC-NGINX_ACCESS-1260": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1260",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1260)"
    ),
    "DEC-APACHE_ERROR-1261": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1261",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1261)"
    ),
    "DEC-LINUX_AUTH-1262": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1262",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1262)"
    ),
    "DEC-WIN_EVENT_4624-1263": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1263",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1263)"
    ),
    "DEC-WIN_EVENT_4625-1264": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1264",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1264)"
    ),
    "DEC-AWS_CLOUDTRAIL-1265": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1265",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1265)"
    ),
    "DEC-GCP_AUDIT-1266": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1266",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1266)"
    ),
    "DEC-CISCO_ASA-1267": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1267",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1267)"
    ),
    "DEC-SURICATA_EVE-1268": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1268",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1268)"
    ),
    "DEC-POSTGRES_AUDIT-1269": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1269",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1269)"
    ),
    "DEC-NGINX_ACCESS-1270": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1270",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1270)"
    ),
    "DEC-APACHE_ERROR-1271": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1271",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1271)"
    ),
    "DEC-LINUX_AUTH-1272": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1272",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1272)"
    ),
    "DEC-WIN_EVENT_4624-1273": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1273",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1273)"
    ),
    "DEC-WIN_EVENT_4625-1274": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1274",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1274)"
    ),
    "DEC-AWS_CLOUDTRAIL-1275": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1275",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1275)"
    ),
    "DEC-GCP_AUDIT-1276": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1276",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1276)"
    ),
    "DEC-CISCO_ASA-1277": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1277",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1277)"
    ),
    "DEC-SURICATA_EVE-1278": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1278",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1278)"
    ),
    "DEC-POSTGRES_AUDIT-1279": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1279",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1279)"
    ),
    "DEC-NGINX_ACCESS-1280": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1280",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1280)"
    ),
    "DEC-APACHE_ERROR-1281": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1281",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1281)"
    ),
    "DEC-LINUX_AUTH-1282": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1282",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1282)"
    ),
    "DEC-WIN_EVENT_4624-1283": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1283",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1283)"
    ),
    "DEC-WIN_EVENT_4625-1284": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1284",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1284)"
    ),
    "DEC-AWS_CLOUDTRAIL-1285": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1285",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1285)"
    ),
    "DEC-GCP_AUDIT-1286": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1286",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1286)"
    ),
    "DEC-CISCO_ASA-1287": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1287",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1287)"
    ),
    "DEC-SURICATA_EVE-1288": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1288",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1288)"
    ),
    "DEC-POSTGRES_AUDIT-1289": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1289",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1289)"
    ),
    "DEC-NGINX_ACCESS-1290": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1290",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1290)"
    ),
    "DEC-APACHE_ERROR-1291": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1291",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1291)"
    ),
    "DEC-LINUX_AUTH-1292": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1292",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1292)"
    ),
    "DEC-WIN_EVENT_4624-1293": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1293",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1293)"
    ),
    "DEC-WIN_EVENT_4625-1294": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1294",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1294)"
    ),
    "DEC-AWS_CLOUDTRAIL-1295": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1295",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1295)"
    ),
    "DEC-GCP_AUDIT-1296": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1296",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1296)"
    ),
    "DEC-CISCO_ASA-1297": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1297",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1297)"
    ),
    "DEC-SURICATA_EVE-1298": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1298",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1298)"
    ),
    "DEC-POSTGRES_AUDIT-1299": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1299",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1299)"
    ),
    "DEC-NGINX_ACCESS-1300": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1300",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1300)"
    ),
    "DEC-APACHE_ERROR-1301": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1301",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1301)"
    ),
    "DEC-LINUX_AUTH-1302": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1302",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1302)"
    ),
    "DEC-WIN_EVENT_4624-1303": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1303",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1303)"
    ),
    "DEC-WIN_EVENT_4625-1304": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1304",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1304)"
    ),
    "DEC-AWS_CLOUDTRAIL-1305": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1305",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1305)"
    ),
    "DEC-GCP_AUDIT-1306": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1306",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1306)"
    ),
    "DEC-CISCO_ASA-1307": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1307",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1307)"
    ),
    "DEC-SURICATA_EVE-1308": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1308",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1308)"
    ),
    "DEC-POSTGRES_AUDIT-1309": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1309",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1309)"
    ),
    "DEC-NGINX_ACCESS-1310": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1310",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1310)"
    ),
    "DEC-APACHE_ERROR-1311": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1311",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1311)"
    ),
    "DEC-LINUX_AUTH-1312": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1312",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1312)"
    ),
    "DEC-WIN_EVENT_4624-1313": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1313",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1313)"
    ),
    "DEC-WIN_EVENT_4625-1314": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1314",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1314)"
    ),
    "DEC-AWS_CLOUDTRAIL-1315": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1315",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1315)"
    ),
    "DEC-GCP_AUDIT-1316": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1316",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1316)"
    ),
    "DEC-CISCO_ASA-1317": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1317",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1317)"
    ),
    "DEC-SURICATA_EVE-1318": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1318",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1318)"
    ),
    "DEC-POSTGRES_AUDIT-1319": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1319",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1319)"
    ),
    "DEC-NGINX_ACCESS-1320": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1320",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1320)"
    ),
    "DEC-APACHE_ERROR-1321": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1321",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1321)"
    ),
    "DEC-LINUX_AUTH-1322": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1322",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1322)"
    ),
    "DEC-WIN_EVENT_4624-1323": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1323",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1323)"
    ),
    "DEC-WIN_EVENT_4625-1324": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1324",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1324)"
    ),
    "DEC-AWS_CLOUDTRAIL-1325": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1325",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1325)"
    ),
    "DEC-GCP_AUDIT-1326": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1326",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1326)"
    ),
    "DEC-CISCO_ASA-1327": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1327",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1327)"
    ),
    "DEC-SURICATA_EVE-1328": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1328",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1328)"
    ),
    "DEC-POSTGRES_AUDIT-1329": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1329",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1329)"
    ),
    "DEC-NGINX_ACCESS-1330": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1330",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1330)"
    ),
    "DEC-APACHE_ERROR-1331": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1331",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1331)"
    ),
    "DEC-LINUX_AUTH-1332": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1332",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1332)"
    ),
    "DEC-WIN_EVENT_4624-1333": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1333",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1333)"
    ),
    "DEC-WIN_EVENT_4625-1334": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1334",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1334)"
    ),
    "DEC-AWS_CLOUDTRAIL-1335": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1335",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1335)"
    ),
    "DEC-GCP_AUDIT-1336": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1336",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1336)"
    ),
    "DEC-CISCO_ASA-1337": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1337",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1337)"
    ),
    "DEC-SURICATA_EVE-1338": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1338",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1338)"
    ),
    "DEC-POSTGRES_AUDIT-1339": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1339",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1339)"
    ),
    "DEC-NGINX_ACCESS-1340": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1340",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1340)"
    ),
    "DEC-APACHE_ERROR-1341": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1341",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1341)"
    ),
    "DEC-LINUX_AUTH-1342": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1342",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1342)"
    ),
    "DEC-WIN_EVENT_4624-1343": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1343",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1343)"
    ),
    "DEC-WIN_EVENT_4625-1344": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1344",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1344)"
    ),
    "DEC-AWS_CLOUDTRAIL-1345": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1345",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1345)"
    ),
    "DEC-GCP_AUDIT-1346": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1346",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1346)"
    ),
    "DEC-CISCO_ASA-1347": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1347",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1347)"
    ),
    "DEC-SURICATA_EVE-1348": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1348",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1348)"
    ),
    "DEC-POSTGRES_AUDIT-1349": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1349",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1349)"
    ),
    "DEC-NGINX_ACCESS-1350": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1350",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1350)"
    ),
    "DEC-APACHE_ERROR-1351": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1351",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1351)"
    ),
    "DEC-LINUX_AUTH-1352": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1352",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1352)"
    ),
    "DEC-WIN_EVENT_4624-1353": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1353",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1353)"
    ),
    "DEC-WIN_EVENT_4625-1354": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1354",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1354)"
    ),
    "DEC-AWS_CLOUDTRAIL-1355": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1355",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1355)"
    ),
    "DEC-GCP_AUDIT-1356": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1356",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1356)"
    ),
    "DEC-CISCO_ASA-1357": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1357",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1357)"
    ),
    "DEC-SURICATA_EVE-1358": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1358",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1358)"
    ),
    "DEC-POSTGRES_AUDIT-1359": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1359",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1359)"
    ),
    "DEC-NGINX_ACCESS-1360": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1360",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1360)"
    ),
    "DEC-APACHE_ERROR-1361": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1361",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1361)"
    ),
    "DEC-LINUX_AUTH-1362": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1362",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1362)"
    ),
    "DEC-WIN_EVENT_4624-1363": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1363",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1363)"
    ),
    "DEC-WIN_EVENT_4625-1364": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1364",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1364)"
    ),
    "DEC-AWS_CLOUDTRAIL-1365": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1365",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1365)"
    ),
    "DEC-GCP_AUDIT-1366": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1366",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1366)"
    ),
    "DEC-CISCO_ASA-1367": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1367",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1367)"
    ),
    "DEC-SURICATA_EVE-1368": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1368",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1368)"
    ),
    "DEC-POSTGRES_AUDIT-1369": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1369",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1369)"
    ),
    "DEC-NGINX_ACCESS-1370": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1370",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1370)"
    ),
    "DEC-APACHE_ERROR-1371": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1371",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1371)"
    ),
    "DEC-LINUX_AUTH-1372": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1372",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1372)"
    ),
    "DEC-WIN_EVENT_4624-1373": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1373",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1373)"
    ),
    "DEC-WIN_EVENT_4625-1374": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1374",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1374)"
    ),
    "DEC-AWS_CLOUDTRAIL-1375": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1375",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1375)"
    ),
    "DEC-GCP_AUDIT-1376": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1376",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1376)"
    ),
    "DEC-CISCO_ASA-1377": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1377",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1377)"
    ),
    "DEC-SURICATA_EVE-1378": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1378",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1378)"
    ),
    "DEC-POSTGRES_AUDIT-1379": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1379",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1379)"
    ),
    "DEC-NGINX_ACCESS-1380": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1380",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1380)"
    ),
    "DEC-APACHE_ERROR-1381": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1381",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1381)"
    ),
    "DEC-LINUX_AUTH-1382": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1382",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1382)"
    ),
    "DEC-WIN_EVENT_4624-1383": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1383",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1383)"
    ),
    "DEC-WIN_EVENT_4625-1384": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1384",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1384)"
    ),
    "DEC-AWS_CLOUDTRAIL-1385": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1385",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1385)"
    ),
    "DEC-GCP_AUDIT-1386": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1386",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1386)"
    ),
    "DEC-CISCO_ASA-1387": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1387",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1387)"
    ),
    "DEC-SURICATA_EVE-1388": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1388",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1388)"
    ),
    "DEC-POSTGRES_AUDIT-1389": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1389",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1389)"
    ),
    "DEC-NGINX_ACCESS-1390": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1390",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1390)"
    ),
    "DEC-APACHE_ERROR-1391": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1391",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1391)"
    ),
    "DEC-LINUX_AUTH-1392": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1392",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1392)"
    ),
    "DEC-WIN_EVENT_4624-1393": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1393",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1393)"
    ),
    "DEC-WIN_EVENT_4625-1394": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1394",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1394)"
    ),
    "DEC-AWS_CLOUDTRAIL-1395": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1395",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1395)"
    ),
    "DEC-GCP_AUDIT-1396": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1396",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1396)"
    ),
    "DEC-CISCO_ASA-1397": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1397",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1397)"
    ),
    "DEC-SURICATA_EVE-1398": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1398",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1398)"
    ),
    "DEC-POSTGRES_AUDIT-1399": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1399",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1399)"
    ),
    "DEC-NGINX_ACCESS-1400": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1400",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1400)"
    ),
    "DEC-APACHE_ERROR-1401": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1401",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1401)"
    ),
    "DEC-LINUX_AUTH-1402": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1402",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1402)"
    ),
    "DEC-WIN_EVENT_4624-1403": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1403",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1403)"
    ),
    "DEC-WIN_EVENT_4625-1404": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1404",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1404)"
    ),
    "DEC-AWS_CLOUDTRAIL-1405": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1405",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1405)"
    ),
    "DEC-GCP_AUDIT-1406": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1406",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1406)"
    ),
    "DEC-CISCO_ASA-1407": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1407",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1407)"
    ),
    "DEC-SURICATA_EVE-1408": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1408",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1408)"
    ),
    "DEC-POSTGRES_AUDIT-1409": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1409",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1409)"
    ),
    "DEC-NGINX_ACCESS-1410": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1410",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1410)"
    ),
    "DEC-APACHE_ERROR-1411": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1411",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1411)"
    ),
    "DEC-LINUX_AUTH-1412": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1412",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1412)"
    ),
    "DEC-WIN_EVENT_4624-1413": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1413",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1413)"
    ),
    "DEC-WIN_EVENT_4625-1414": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1414",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1414)"
    ),
    "DEC-AWS_CLOUDTRAIL-1415": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1415",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1415)"
    ),
    "DEC-GCP_AUDIT-1416": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1416",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1416)"
    ),
    "DEC-CISCO_ASA-1417": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1417",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1417)"
    ),
    "DEC-SURICATA_EVE-1418": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1418",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1418)"
    ),
    "DEC-POSTGRES_AUDIT-1419": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1419",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1419)"
    ),
    "DEC-NGINX_ACCESS-1420": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1420",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1420)"
    ),
    "DEC-APACHE_ERROR-1421": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1421",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1421)"
    ),
    "DEC-LINUX_AUTH-1422": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1422",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1422)"
    ),
    "DEC-WIN_EVENT_4624-1423": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1423",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1423)"
    ),
    "DEC-WIN_EVENT_4625-1424": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1424",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1424)"
    ),
    "DEC-AWS_CLOUDTRAIL-1425": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1425",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1425)"
    ),
    "DEC-GCP_AUDIT-1426": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1426",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1426)"
    ),
    "DEC-CISCO_ASA-1427": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1427",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1427)"
    ),
    "DEC-SURICATA_EVE-1428": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1428",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1428)"
    ),
    "DEC-POSTGRES_AUDIT-1429": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1429",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1429)"
    ),
    "DEC-NGINX_ACCESS-1430": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1430",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1430)"
    ),
    "DEC-APACHE_ERROR-1431": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1431",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1431)"
    ),
    "DEC-LINUX_AUTH-1432": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1432",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1432)"
    ),
    "DEC-WIN_EVENT_4624-1433": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1433",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1433)"
    ),
    "DEC-WIN_EVENT_4625-1434": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1434",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1434)"
    ),
    "DEC-AWS_CLOUDTRAIL-1435": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1435",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1435)"
    ),
    "DEC-GCP_AUDIT-1436": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1436",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1436)"
    ),
    "DEC-CISCO_ASA-1437": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1437",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1437)"
    ),
    "DEC-SURICATA_EVE-1438": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1438",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1438)"
    ),
    "DEC-POSTGRES_AUDIT-1439": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1439",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1439)"
    ),
    "DEC-NGINX_ACCESS-1440": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1440",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1440)"
    ),
    "DEC-APACHE_ERROR-1441": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1441",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1441)"
    ),
    "DEC-LINUX_AUTH-1442": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1442",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1442)"
    ),
    "DEC-WIN_EVENT_4624-1443": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1443",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1443)"
    ),
    "DEC-WIN_EVENT_4625-1444": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1444",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1444)"
    ),
    "DEC-AWS_CLOUDTRAIL-1445": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1445",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1445)"
    ),
    "DEC-GCP_AUDIT-1446": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1446",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1446)"
    ),
    "DEC-CISCO_ASA-1447": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1447",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1447)"
    ),
    "DEC-SURICATA_EVE-1448": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1448",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1448)"
    ),
    "DEC-POSTGRES_AUDIT-1449": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1449",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1449)"
    ),
    "DEC-NGINX_ACCESS-1450": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1450",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1450)"
    ),
    "DEC-APACHE_ERROR-1451": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1451",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1451)"
    ),
    "DEC-LINUX_AUTH-1452": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1452",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1452)"
    ),
    "DEC-WIN_EVENT_4624-1453": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1453",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1453)"
    ),
    "DEC-WIN_EVENT_4625-1454": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1454",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1454)"
    ),
    "DEC-AWS_CLOUDTRAIL-1455": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1455",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1455)"
    ),
    "DEC-GCP_AUDIT-1456": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1456",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1456)"
    ),
    "DEC-CISCO_ASA-1457": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1457",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1457)"
    ),
    "DEC-SURICATA_EVE-1458": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1458",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1458)"
    ),
    "DEC-POSTGRES_AUDIT-1459": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1459",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1459)"
    ),
    "DEC-NGINX_ACCESS-1460": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1460",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1460)"
    ),
    "DEC-APACHE_ERROR-1461": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1461",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1461)"
    ),
    "DEC-LINUX_AUTH-1462": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1462",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1462)"
    ),
    "DEC-WIN_EVENT_4624-1463": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1463",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1463)"
    ),
    "DEC-WIN_EVENT_4625-1464": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1464",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1464)"
    ),
    "DEC-AWS_CLOUDTRAIL-1465": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1465",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1465)"
    ),
    "DEC-GCP_AUDIT-1466": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1466",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1466)"
    ),
    "DEC-CISCO_ASA-1467": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1467",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1467)"
    ),
    "DEC-SURICATA_EVE-1468": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1468",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1468)"
    ),
    "DEC-POSTGRES_AUDIT-1469": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1469",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1469)"
    ),
    "DEC-NGINX_ACCESS-1470": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1470",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1470)"
    ),
    "DEC-APACHE_ERROR-1471": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1471",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1471)"
    ),
    "DEC-LINUX_AUTH-1472": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1472",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1472)"
    ),
    "DEC-WIN_EVENT_4624-1473": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1473",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1473)"
    ),
    "DEC-WIN_EVENT_4625-1474": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1474",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1474)"
    ),
    "DEC-AWS_CLOUDTRAIL-1475": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1475",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1475)"
    ),
    "DEC-GCP_AUDIT-1476": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1476",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1476)"
    ),
    "DEC-CISCO_ASA-1477": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1477",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1477)"
    ),
    "DEC-SURICATA_EVE-1478": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1478",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1478)"
    ),
    "DEC-POSTGRES_AUDIT-1479": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1479",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1479)"
    ),
    "DEC-NGINX_ACCESS-1480": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1480",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1480)"
    ),
    "DEC-APACHE_ERROR-1481": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1481",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1481)"
    ),
    "DEC-LINUX_AUTH-1482": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1482",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1482)"
    ),
    "DEC-WIN_EVENT_4624-1483": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1483",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1483)"
    ),
    "DEC-WIN_EVENT_4625-1484": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1484",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1484)"
    ),
    "DEC-AWS_CLOUDTRAIL-1485": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1485",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1485)"
    ),
    "DEC-GCP_AUDIT-1486": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1486",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1486)"
    ),
    "DEC-CISCO_ASA-1487": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1487",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1487)"
    ),
    "DEC-SURICATA_EVE-1488": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1488",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1488)"
    ),
    "DEC-POSTGRES_AUDIT-1489": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1489",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1489)"
    ),
    "DEC-NGINX_ACCESS-1490": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1490",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1490)"
    ),
    "DEC-APACHE_ERROR-1491": DecoderDefinition(
        decoder_id="DEC-APACHE_ERROR-1491",
        log_source="APACHE_ERROR",
        event_type="Web Error",
        regex_pattern="^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)",
        compiled_regex=re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Error events (Variant #1491)"
    ),
    "DEC-LINUX_AUTH-1492": DecoderDefinition(
        decoder_id="DEC-LINUX_AUTH-1492",
        log_source="LINUX_AUTH",
        event_type="SSH / Auth",
        regex_pattern="^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)",
        compiled_regex=re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for SSH / Auth events (Variant #1492)"
    ),
    "DEC-WIN_EVENT_4624-1493": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4624-1493",
        log_source="WIN_EVENT_4624",
        event_type="Windows Logon",
        regex_pattern="^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Success: User=(?P<user>\S+) Domain=(?P<domain>\S+) LogonType=(?P<type>\d+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Logon events (Variant #1493)"
    ),
    "DEC-WIN_EVENT_4625-1494": DecoderDefinition(
        decoder_id="DEC-WIN_EVENT_4625-1494",
        log_source="WIN_EVENT_4625",
        event_type="Windows Failed Logon",
        regex_pattern="^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^Logon Failure: User=(?P<user>\S+) Domain=(?P<domain>\S+) Status=(?P<status>\S+) IP=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Windows Failed Logon events (Variant #1494)"
    ),
    "DEC-AWS_CLOUDTRAIL-1495": DecoderDefinition(
        decoder_id="DEC-AWS_CLOUDTRAIL-1495",
        log_source="AWS_CLOUDTRAIL",
        event_type="Cloud Audit",
        regex_pattern="^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^AWS CloudTrail: eventName=(?P<event>\S+) userIdentity=(?P<user>\S+) sourceIPAddress=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Cloud Audit events (Variant #1495)"
    ),
    "DEC-GCP_AUDIT-1496": DecoderDefinition(
        decoder_id="DEC-GCP_AUDIT-1496",
        log_source="GCP_AUDIT",
        event_type="GCP Audit",
        regex_pattern="^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)",
        compiled_regex=re.compile(r"^GCP AuditLog: method=(?P<method>\S+) principal=(?P<user>\S+) callerIp=(?P<ip>\S+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for GCP Audit events (Variant #1496)"
    ),
    "DEC-CISCO_ASA-1497": DecoderDefinition(
        decoder_id="DEC-CISCO_ASA-1497",
        log_source="CISCO_ASA",
        event_type="Firewall",
        regex_pattern="^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)",
        compiled_regex=re.compile(r"^%ASA-(?P<level>\d)-(?P<tag>\d+): Built inbound TCP connection (?P<conn_id>\d+) for (?P<src_ip>\S+)/(?P<src_port>\d+) to (?P<dst_ip>\S+)/(?P<dst_port>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Firewall events (Variant #1497)"
    ),
    "DEC-SURICATA_EVE-1498": DecoderDefinition(
        decoder_id="DEC-SURICATA_EVE-1498",
        log_source="SURICATA_EVE",
        event_type="NIDS Alert",
        regex_pattern="^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]",
        compiled_regex=re.compile(r"^Suricata: \[(?P<sid>\d+)\] (?P<alert_msg>[^\[]+) \[(?P<src_ip>\S+):(?P<src_port>\d+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)\]"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for NIDS Alert events (Variant #1498)"
    ),
    "DEC-POSTGRES_AUDIT-1499": DecoderDefinition(
        decoder_id="DEC-POSTGRES_AUDIT-1499",
        log_source="POSTGRES_AUDIT",
        event_type="Database Query",
        regex_pattern="^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)",
        compiled_regex=re.compile(r"^(?P<time>[^ ]+ [^ ]+) \[(?P<pid>\d+)\]: \[(?P<line>\d+)\] user=(?P<user>\S+),db=(?P<db>\S+),app=(?P<app>\S+),client=(?P<ip>\S+) LOG:  statement: (?P<sql>.*)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Database Query events (Variant #1499)"
    ),
    "DEC-NGINX_ACCESS-1500": DecoderDefinition(
        decoder_id="DEC-NGINX_ACCESS-1500",
        log_source="NGINX_ACCESS",
        event_type="Web Access",
        regex_pattern="^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)",
        compiled_regex=re.compile(r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>\S+) (?P<uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<bytes>\d+)"),
        field_mapping={"src_ip": "ip", "event_user": "user", "timestamp": "time"},
        description="Decoder rule for Web Access events (Variant #1500)"
    ),
}

def decode_raw_event(log_line: str) -> Optional[Dict[str, Any]]:
    for dec in SIEM_DECODER_REGISTRY.values():
        m = dec.compiled_regex.search(log_line)
        if m:
            res = m.groupdict()
            res["_decoder_id"] = dec.decoder_id
            res["_log_source"] = dec.log_source
            return res
    return None
