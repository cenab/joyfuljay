"""Port classification utility for Tranalyzer compatibility."""

from __future__ import annotations

# Well-known ports classification
# Based on IANA assignments and Tranalyzer categories
WELL_KNOWN_PORTS: dict[int, tuple[str, int]] = {
    # System ports (0-1023)
    20: ("ftp-data", 1),
    21: ("ftp", 1),
    22: ("ssh", 1),
    23: ("telnet", 1),
    25: ("smtp", 1),
    53: ("dns", 1),
    67: ("dhcp", 1),
    68: ("dhcp", 1),
    69: ("tftp", 1),
    80: ("http", 1),
    110: ("pop3", 1),
    119: ("nntp", 1),
    123: ("ntp", 1),
    143: ("imap", 1),
    161: ("snmp", 1),
    162: ("snmp-trap", 1),
    443: ("https", 1),
    445: ("smb", 1),
    465: ("smtps", 1),
    514: ("syslog", 1),
    587: ("smtp-submission", 1),
    636: ("ldaps", 1),
    853: ("dns-over-tls", 1),
    993: ("imaps", 1),
    995: ("pop3s", 1),
    # Registered ports (1024-49151)
    1080: ("socks", 2),
    1194: ("openvpn", 2),
    1433: ("mssql", 2),
    1521: ("oracle", 2),
    1723: ("pptp", 2),
    3306: ("mysql", 2),
    3389: ("rdp", 2),
    5060: ("sip", 2),
    5061: ("sips", 2),
    5222: ("xmpp", 2),
    5432: ("postgresql", 2),
    5900: ("vnc", 2),
    6379: ("redis", 2),
    6667: ("irc", 2),
    8080: ("http-alt", 2),
    8443: ("https-alt", 2),
    8888: ("http-alt", 2),
    9000: ("php-fpm", 2),
    9200: ("elasticsearch", 2),
    27017: ("mongodb", 2),
}


def classify_port(port: int) -> tuple[str, int]:
    """Classify a port number.

    Args:
        port: The port number to classify.

    Returns:
        Tuple of (class_name, class_number):
        - class_name: Human-readable classification
        - class_number: Numeric class (1=well-known, 2=registered, 3=dynamic)
    """
    if port in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[port]

    if port < 1024:
        return ("system", 1)
    elif port < 49152:
        return ("registered", 2)
    else:
        return ("dynamic", 3)


def get_port_class_name(port: int) -> str:
    """Get the class name for a port.

    Args:
        port: The port number.

    Returns:
        String classification of the port.
    """
    return classify_port(port)[0]


def get_port_class_number(port: int) -> int:
    """Get the class number for a port.

    Args:
        port: The port number.

    Returns:
        Numeric classification (1=well-known, 2=registered, 3=dynamic).
    """
    return classify_port(port)[1]
