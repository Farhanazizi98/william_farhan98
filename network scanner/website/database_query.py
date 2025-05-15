from . import get_db
def get_all_projects_for_user(user_id, scan_type):
    database = get_db()
    cursor = database.cursor()
    
    cursor.execute("""
        SELECT id, name, created_at 
        FROM projects 
        WHERE user_id = ? AND scan_type = ?
        ORDER BY id DESC
    """, (user_id, scan_type))
    
    return cursor.fetchall()

def count_projects_for_user(user_id, scan_type):
    database = get_db()
    cursor = database.cursor()
    
    cursor.execute("""
        SELECT COUNT(*) FROM projects 
        WHERE user_id = ? AND scan_type = ?
    """, (user_id, scan_type))
    
    return cursor.fetchone()[0]


def insert_project(user_id, name, created_at, scan_type):
    database = get_db()
    cursor = database.cursor()
    
    cursor.execute("""
        INSERT INTO projects (user_id, name, created_at, scan_type)
        VALUES (?, ?, ?, ?)
    """, (user_id, name, created_at, scan_type))
    
    database.commit()
    
    return cursor.lastrowid


def insert_to_summary(scan_time, total_hosts_scanned, host_up, total_scan_time, time_template):
    database = get_db()
    cursor = database.cursor()
    
    cursor.execute("""
        INSERT INTO icmp_scan_summary (scan_time, total_hosts_scanned, host_up, total_scan_time, time_template)
        VALUES (?, ?, ?, ?, ?)
    """, (scan_time, total_hosts_scanned, host_up, total_scan_time, time_template))
    
    database.commit()
    
    return cursor.lastrowid

def Insert_to_icmp_scan(ip, latency, scan_id, user_id, project_id):
    database = get_db()
    cursor = database.cursor()
    
    cursor.execute("""
        INSERT INTO icmp_scan (ip, latency, scan_id, user_id, project_id)
        VALUES (?, ?, ?, ?, ?)
    """, (ip, latency, scan_id, user_id, project_id))

    database.commit()
    return None

def get_all_icmp_scans_for_project(project_id, user_id):
    database = get_db()
    cursor = database.cursor()
    
    cursor.execute("""
        SELECT i.ip, i.latency, s.scan_time, s.total_hosts_scanned, s.host_up, s.total_scan_time, s.time_template
        FROM icmp_scan i, icmp_scan_summary s
        WHERE i.scan_id = s.id
        AND i.project_id = ? AND i.user_id = ?
        ORDER BY s.scan_time DESC
    """, (project_id, user_id))
    
    return cursor.fetchall()

def insert_to_tcp_udp_summary(scan_time, total_scanned_hosts, host_up, total_scan_time, port_range, time_template):
    database = get_db()
    cursor = database.cursor()
    cursor.execute("""
        INSERT INTO TCP_UDP_scan_summary 
        (scan_time, total_scanned_hosts, host_up, total_scan_time, port_range, time_template)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (scan_time, total_scanned_hosts, host_up, total_scan_time, port_range, time_template))
    database.commit()
    return cursor.lastrowid

def get_all_TCP_UDP_scans_for_project(project_id, user_id):
    database = get_db()
    cursor = database.cursor()
    cursor.execute("""  
        SELECT t.target, t.port, t.state, t.service, t.scan_type, s.scan_time, s.total_scanned_hosts, s.host_up, s.total_scan_time, s.port_range, s.time_template
        FROM TCP_UDP_SCAN t, TCP_UDP_scan_summary s
        WHERE t.scan_id = s.id
        AND t.project_id = ? AND t.user_id = ?
        ORDER BY s.scan_time DESC
    """, (project_id, user_id))
    return cursor.fetchall()

def insert_to_TCP_UDP_scan(project_id, user_id, target, port, state, service, scan_type, scan_id):
    database = get_db()
    cursor = database.cursor()
    cursor.execute("""
        INSERT INTO TCP_UDP_SCAN (project_id, user_id, target, port, state, service, scan_type, scan_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (project_id, user_id, target, port, state, service, scan_type, scan_id))
    database.commit()
    return None


def insert_to_ip_protocol_scan_summary(scan_time, total_hosts_scanned, host_up, total_scan_time, time_template):
    database = get_db()
    cursor = database.cursor()
    
    cursor.execute("""
        INSERT INTO IP_PROTOCOL_SCAN_SUMMARY (scan_time, total_hosts_scanned, host_up, total_scan_time, time_template)
        VALUES (?, ?, ?, ?, ?)
    """, (scan_time, total_hosts_scanned, host_up, total_scan_time, time_template))
    
    database.commit()
    
    return cursor.lastrowid

def insert_to_ip_protocol_scan(ip, latency, scan_id, protocol, state, service, user_id, project_id):
    database = get_db()
    cursor = database.cursor()
    cursor.execute("""
        INSERT INTO IP_PROTOCOL_SCAN (ip, latency, scan_id, protocol, state, service, user_id, project_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (ip, latency, scan_id, protocol, state, service, user_id, project_id))
    database.commit()
    return None

def get_all_ip_protocol_scans_for_project(project_id, user_id):
    database = get_db()
    cursor = database.cursor()
    cursor.execute("""
        SELECT i.ip, i.latency, s.scan_time, i.protocol, i.state, i.service, 
               s.total_hosts_scanned, s.host_up, s.total_scan_time, s.time_template
        FROM IP_PROTOCOL_SCAN i, IP_PROTOCOL_SCAN_SUMMARY s
        WHERE i.scan_id = s.id
        AND i.project_id = ? AND i.user_id = ?
        ORDER BY s.scan_time DESC
    """, (project_id, user_id))
    return cursor.fetchall()


#source ----------------- https://docs.python.org/3/library/sqlite3.html ------------------ 

