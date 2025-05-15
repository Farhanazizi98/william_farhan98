import re

def get_ip_addresses_by_its_pattern(result):
    ip_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
    return re.findall(ip_pattern, result)

def get_latency_by_its_pattern(result):
    latency_pattern = re.compile(r"\(([\d+.]+s)")
    return re.findall(latency_pattern, result)

def get_total_scanned_host_by_its_pattern(result):
    total_scanned_host_pattern = re.compile(r"Nmap done: (\d+)")
    return re.findall(total_scanned_host_pattern, result)

def get_total_up_host_by_its_pattern(result):
    total_up_host_pattern = re.compile(r"(\d+) hosts? up")
    return re.findall(total_up_host_pattern, result)

def get_total_scanned_time_by_its_pattern(result):
    total_scanned_time_pattern = re.compile(r"scanned in (\d+\.\d+) seconds")
    return re.findall(total_scanned_time_pattern, result)

def get_block_pattern(result):
    block_pattern = re.compile(r"\n\n")
    return re.split(block_pattern, result)

def get_port_info_by_its_pattern(result):
    port_pattern = re.compile(r"(\d+/\w+)\s+([\w|]+)\s+(\S+)")
    return re.findall(port_pattern, result)

def get_two_scan_block_by_its_pattern(result):
    two_scan_block_pattern = re.compile(r"(?=Nmap scan report for)")
    return re.split(two_scan_block_pattern, result)

def get_not_found_any_result_pattern(result):
    not_found_any_result_pattern = re.compile(r"\d+\s+\w+\|\w+")
    return re.findall(not_found_any_result_pattern, result)

def get_protocol_state_service_by_its_pattern(result):
    protocol_state_service_pattern = re.compile(r"^(\d+)\s+([a-z]+(?:\|[a-z]+)*)\s+([a-z]+)$", re.MULTILINE)
    return re.findall(protocol_state_service_pattern, result)


#source ----------------- https://docs.python.org/3/howto/regex.html ------------------