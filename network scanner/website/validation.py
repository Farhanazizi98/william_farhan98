import re

def validate_ip_address(ip_address):
    ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:(?:\/\d{1,2})|(?:-\d{1,3}))?\b")
    return ip_pattern.match(ip_address)

def validate_port_range(port_range):
    port_pattern = re.compile(r"^\d+(-\d+)?$")
    return port_pattern.match(port_range)


