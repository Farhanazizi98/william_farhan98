from flask import Blueprint, render_template, request, redirect, url_for, flash
import subprocess
from flask_login import login_required, current_user
from .database_query import get_all_projects_for_user, insert_project, count_projects_for_user, insert_to_summary, Insert_to_icmp_scan, get_all_icmp_scans_for_project, insert_to_tcp_udp_summary, get_all_TCP_UDP_scans_for_project, insert_to_TCP_UDP_scan, insert_to_ip_protocol_scan_summary, insert_to_ip_protocol_scan, get_all_ip_protocol_scans_for_project
from .plotting import create_network_plot, create_tcp_udp_plot

from datetime import datetime
from .pattern import get_ip_addresses_by_its_pattern, get_latency_by_its_pattern, get_total_scanned_host_by_its_pattern, get_total_up_host_by_its_pattern, get_total_scanned_time_by_its_pattern, get_block_pattern, get_port_info_by_its_pattern, get_two_scan_block_by_its_pattern, get_protocol_state_service_by_its_pattern
from .validation import validate_ip_address, validate_port_range
views = Blueprint("views", __name__)

@views.route("/", methods=["GET", "POST"])
@login_required
def home():
    return redirect(url_for("views.icmp_scan"))


#ICMAP SCAN ----------------------------------------------------------------
@views.route("/icmp-scan", methods=['GET', 'POST'])
@login_required
def icmp_scan():

    plots = {}

    try:
        # Gets all projects for a user

        if request.method == 'POST' and 'new_project' in request.form:
            count = count_projects_for_user(current_user.id, 'ICMP')
            new_project_name = f"Project {count + 1}"  
            
            insert_project(current_user.id, new_project_name, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'ICMP')
            return redirect(url_for('views.icmp_scan'))

        all_projects = get_all_projects_for_user(current_user.id, 'ICMP')
        # create first project, if no project found

        if not all_projects:
            project_id =insert_project(current_user.id, "Project 1", datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'ICMP')
            project_name = "Project 1"
            all_projects = [(project_id, project_name, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))]
        else:
            project_id = request.args.get('project_id', all_projects[0][0])
            try:
                project_name = next(p[1] for p in all_projects if str(p[0]) == str(project_id))
            except StopIteration:
                project_id = all_projects[0][0]
                project_name = all_projects[0][1]


        # get target, os_type, timing_template from form
        if request.method == 'POST':
            target = request.form.get('target')
            os_type = request.form.get('os_type', 'mac')
            timing_template = request.form.get('timing_template', 'normal')
            
            if timing_template == 'paranoid':
                timing_template = '-T0'
            elif timing_template == 'sneaky':
                timing_template = '-T1'
            elif timing_template == 'polite':
                timing_template = '-T2'
            elif timing_template == 'normal':
                timing_template = '-T3'
            elif timing_template == 'aggressive':
                timing_template = '-T4'
            elif timing_template == 'insane':
                timing_template = '-T5'
                
              # Default to mac if not specified

            
            
            if target:
                # check if target is valid ip address
                if not validate_ip_address(target):
                    flash("Invalid IP address format", "error")
                    # Get stored data and create plots before returning
                    stored_data = get_all_icmp_scans_for_project(project_id, current_user.id)
                    
                    # Create plots for stored data, when user insert invalid ip address otherwise it will not display the plots
                    if stored_data:
                        scan_groups = {}
                        for scan in stored_data:
                            if scan[2] not in scan_groups:
                                scan_groups[scan[2]] = []
                            scan_groups[scan[2]].append(scan)

                        for scan_time, scans in scan_groups.items():
                            plots[scan_time] = create_network_plot(scans)
                            
                    return render_template("icmp_subnet.html",
                                        user=current_user,
                                        project_id=project_id,
                                        project_name=project_name,
                                        projects=all_projects,
                                        stored_data=stored_data,
                                        plot_div=plots)
                else:
                    flash("Scan completed successfully", "success")

                # Build command based on OS type
                if os_type == 'mac':
                    nmap_command = ["sudo", 'nmap', timing_template, '-sn', '-PE', target]
                else:
                    nmap_command = [ 'nmap', timing_template, '-sn', '-PE', target]
                    
                # run nmap command via subprocess
                result = subprocess.run(nmap_command, capture_output=True, text=True, check=True)

                ip_addresses = get_ip_addresses_by_its_pattern(result.stdout)
                latency = get_latency_by_its_pattern(result.stdout)
                total_scanned_host = get_total_scanned_host_by_its_pattern(result.stdout)
                total_up_host = get_total_up_host_by_its_pattern(result.stdout)
                total_scanned_time = get_total_scanned_time_by_its_pattern(result.stdout)

                # check if no ip address found, if not, no reachable host found
                if total_up_host[0] == "0":
                    flash("No IP addresses found in the scan results", "error")
                    return redirect(url_for('views.icmp_scan', project_id=project_id))

                scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                # insert to the ICMP scan summary to database
                scan_id = insert_to_summary(
                    scan_time, 
                    total_scanned_host[0], 
                    total_up_host[0], 
                    total_scanned_time[0],
                    timing_template  
                )

                # Store  retreived IP address and latency to ICMP database
                for ip, lat in zip(ip_addresses, latency):
                    Insert_to_icmp_scan(str(ip), str(lat), scan_id, current_user.id, project_id)

                # Get retreived scan data from database
                stored_data = get_all_icmp_scans_for_project(project_id, current_user.id)

                # Group scans by item
                scan_groups = {}
                for scan in stored_data:
                    if scan[2] not in scan_groups:
                        scan_groups[scan[2]] = []
                    scan_groups[scan[2]].append(scan)

                # Create plot for each scan group by item
                for scan_time, scans in scan_groups.items():
                    plots[scan_time] = create_network_plot(scans)

                # Redirect after all IPs are processed
                return redirect(url_for('views.icmp_scan', project_id=project_id))
                
                

                

        # Get stored data for display from database when user open the page
        stored_data = get_all_icmp_scans_for_project(project_id, current_user.id)

        # Create plots for stored data from database when user open the page
        scan_groups = {}
        for scan in stored_data:
            if scan[2] not in scan_groups:
                scan_groups[scan[2]] = []
            scan_groups[scan[2]].append(scan)

        for scan_time, scans in scan_groups.items():
            plots[scan_time] = create_network_plot(scans)

        # return the template with the stored data, user, project_id, project_name, projects, and plots
        return render_template("icmp_subnet.html", 
                                              stored_data=stored_data, 
                                              user=current_user,
                                              project_id=project_id,
                                              project_name=project_name,
                                              projects=all_projects,
                                              plot_div=plots)
        
        
    # handle exception
    except Exception as e:
        print(f"Database error: {str(e)}")
        return render_template("icmp_subnet.html",
            error=f"Database error: {str(e)}",
            user=current_user,
            )

#TCP/UDP SCAN ----------------------------------------------------------------
@views.route("/tcp-udp-scan", methods=['GET', 'POST'])
@login_required
def tcp_udp_scan():
    try:
       
        # initialize plots
        plots = {} 

        # Handle new project creation for TCP/UDP scan
        if request.method == 'POST' and 'new_project' in request.form:
            #count the number of projects for the user
            count = count_projects_for_user(current_user.id, 'port_scan')
            new_project_name = f"Project {count + 1}"
            #insert project to database
            insert_project(current_user.id, new_project_name, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'port_scan')
            return redirect(url_for('views.tcp_udp_scan'))

         
        
        # Get all projects for the user
        all_projects=get_all_projects_for_user(current_user.id, 'port_scan')

        # if no project found, create a new project
        if not all_projects:
            project_id =insert_project(current_user.id, "Project 1", datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'port_scan')
            project_name = "Project 1"
            all_projects = [(project_id, project_name, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))]
        else:
            project_id = request.args.get('project_id', all_projects[0][0])
            try:
                project_name = next(p[1] for p in all_projects if str(p[0]) == str(project_id))
            except StopIteration:
                project_id = all_projects[0][0]
                project_name = all_projects[0][1]

        

        # if method is post, get target, ports, scan_type, timing_template, os_type from form
        if request.method == 'POST':
            target = request.form.get('target')
            port_range = request.form.get('ports')
            scan_type = request.form.get('scan_type')
            timing_template = request.form.get('timing_template')
            os_type = request.form.get('os_type')

            if port_range:
                ports = port_range
            else:
                # default port range
                ports = '1-1023'

            if timing_template:
                if timing_template == 'paranoid':
                    timing_template = '-T0'
                elif timing_template == 'sneaky':
                    timing_template = '-T1'
                elif timing_template == 'polite':
                    timing_template = '-T2' 
                elif timing_template == 'normal':
                    timing_template = '-T3'
                elif timing_template == 'aggressive':
                    timing_template = '-T4'
                elif timing_template == 'insane':
                    timing_template = '-T5'

            


            if target:
                # check if target is valid ip address
                if not validate_ip_address(target) or not validate_port_range(ports):
                    flash("Invalid IP address format", "error")
                    
                    latest_scan = get_all_TCP_UDP_scans_for_project(project_id, current_user.id)
                    
                    # Create plots for stored data, when user insert invalid ip address otherwise it will not display the plots
                    if latest_scan:
                        scan_groups = {}
                        for scan in latest_scan:
                            scan_time = scan[5]  
                            if scan_time not in scan_groups:
                                scan_groups[scan_time] = []
                            scan_groups[scan_time].append(scan)

                        # Create plot for each scan group
                        for scan_time, scans in scan_groups.items():
                            try:
                                plots[scan_time] = create_tcp_udp_plot(scans)
                            except Exception as e:
                                print(f"Plotting error: {str(e)}")
                                continue
                    
                    return render_template("tcp_udp_scan.html",
                                        user=current_user,
                                        project_id=project_id,
                                        project_name=project_name,
                                        projects=all_projects,
                                        latest_scan=latest_scan,
                                        plot_div=plots)
                else:
                    flash("Scan completed successfully", "success")

                # build nmap command based on os_type
                if os_type == 'mac':
                    nmap_command = ["sudo", "nmap", timing_template]
                else:
                    nmap_command = ["nmap", timing_template]
                # add ports to nmap command
                nmap_command.extend(["-p", ports])
                
                # Add scan type
                if scan_type == 'syn':
                    nmap_command.append('-sS')
                elif scan_type == 'udp':
                    nmap_command.append('-sU')
                elif scan_type == 'ack':
                    nmap_command.append('-sA')
                elif scan_type == 'fin':
                    nmap_command.append('-sF')
                elif scan_type == 'null':
                    nmap_command.append('-sN')
                elif scan_type == 'xmas':
                    nmap_command.append('-sX')
                elif scan_type == 'syn_udp':
                    nmap_command.extend(['-sS', '-sU'])
                elif scan_type == 'fin_udp':
                    nmap_command.extend(['-sF', '-sU'])
                elif scan_type == 'null_udp':
                    nmap_command.extend(['-sN', '-sU'])
                elif scan_type == 'xmas_udp':
                    nmap_command.extend(['-sX', '-sU'])
                
                
                
                # add target to nmap command
                nmap_command.append(target)

                # run nmap command via subprocess
                result = subprocess.run(nmap_command, capture_output=True, text=True)



                
                
                scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                # Pattern for get scan info from nmap output
                scan_blocks = get_block_pattern(result.stdout)
                two_scan_blocks = get_two_scan_block_by_its_pattern(result.stdout)
                port_matches_cheack = get_port_info_by_its_pattern(result.stdout)
                host_up = get_total_up_host_by_its_pattern(result.stdout)
                total_scanned_hosts = get_total_scanned_host_by_its_pattern(result.stdout)
                total_scan_time = get_total_scanned_time_by_its_pattern(result.stdout)

                # Convert to proper types
                host_up = int(host_up[0]) 
                total_scanned_hosts = int(total_scanned_hosts[0]) 
                total_scan_time = float(total_scan_time[0])

                # check if no open ports found
                if not port_matches_cheack:
                    flash("No open ports found", "error")
                    return redirect(url_for('views.tcp_udp_scan', project_id=project_id))
                
                # insert to tcp_udp_summary
                scan_id = insert_to_tcp_udp_summary(
                    scan_time,
                    total_scanned_hosts,
                    host_up,
                    total_scan_time,
                    ports,  
                    timing_template 
                )

                # split ports
                ports = ports.split('-')

                # check if ports is single or range, if range betwen 1 and 26, use two scan blocks and extract ip address and port from scan_blocks. 
                if len(ports)==1 or (len(ports) == 2 and int(ports[1]) - int(ports[0]) < 26):

                    for block_x in two_scan_blocks:
                        if block_x:

                            #ip_match = ip_pattern.findall(block_x)
                            ip_match = get_ip_addresses_by_its_pattern(block_x)
                            if ip_match:
                                #port_matches_x = port_pattern.findall(block_x)
                                port_matches_x = get_port_info_by_its_pattern(block_x)
                                for m in port_matches_x:
                                    insert_to_TCP_UDP_scan(project_id, current_user.id, ip_match[0], m[0], m[1], m[2], scan_type.upper(), scan_id)
                
                else:
                    #extract ip address and port from scan_blocks
                    for block in scan_blocks:
                        #extract ip address from scan_blocks
                        ip_match = get_ip_addresses_by_its_pattern(block)
                        if ip_match:
                            
                            ip_address = ip_match[0]  
                            port_matches = get_port_info_by_its_pattern(block)

                            
                            for m in port_matches:
                                insert_to_TCP_UDP_scan(
                                    project_id, 
                                    current_user.id, 
                                    ip_address, 
                                    m[0], 
                                    m[1], 
                                    m[2], 
                                    scan_type.upper(),
                                    scan_id
                                )
                                   
                    return redirect(url_for('views.tcp_udp_scan', project_id=project_id))

        latest_scan = get_all_TCP_UDP_scans_for_project(project_id, current_user.id)



        # After fetching latest_scan, group by scan time and create plots
        if latest_scan:
            scan_groups = {}
            for scan in latest_scan:
                scan_time = scan[5]  
                if scan_time not in scan_groups:
                    scan_groups[scan_time] = []
                scan_groups[scan_time].append(scan)

            # Create plot for each scan group
            for scan_time, scans in scan_groups.items():
                try:
                    plots[scan_time] = create_tcp_udp_plot(scans)
                except Exception as e:
                    print(f"Plotting error: {str(e)}")
                    continue
        
        # return the template with the latest_scan information
        return render_template("tcp_udp_scan.html",
                            latest_scan=latest_scan,
                            user=current_user,
                            project_id=project_id,
                            project_name=project_name,
                            projects=all_projects,
                            plot_div=plots,
                            )

    except Exception as e:
        print(f"Database error: {str(e)}")
        return render_template("tcp_udp_scan.html", 
                            error=f"Database error: {str(e)}", 
                            user=current_user,
                            )

#IP PROTOCOL SCAN ----------------------------------------------------------------
@views.route("/ip_protocol_scan", methods=['GET', 'POST'])
@login_required
def ip_protocol_scan():
    try:

    # Get IP protocol projects
        if request.method == 'POST' and 'new_project' in request.form:
            count = count_projects_for_user(current_user.id, 'ip_protocol_scan')
            new_project_name = f"Project {count + 1}"
            insert_project(current_user.id, new_project_name, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'ip_protocol_scan')
            return redirect(url_for('views.ip_protocol_scan'))
        
        all_projects = get_all_projects_for_user(current_user.id, 'ip_protocol_scan')

        # if no project found, create a new project
        if not all_projects:
            project_id = insert_project(current_user.id, "Project 1", datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'ip_protocol_scan')
            project_name = "Project 1"
            all_projects = [(project_id, project_name, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))]
        else:
            project_id = request.args.get('project_id', all_projects[0][0])
            try:
                project_name = next(p[1] for p in all_projects if str(p[0]) == str(project_id))
            except StopIteration:
                # If project_id not found, use the first project
                project_id = all_projects[0][0]
                project_name = all_projects[0][1]



        if request.method == 'POST':
            #get target, timing_template, os_type from form
            target = request.form.get('target')
            timing_template = request.form.get('timing_template')
            os_type = request.form.get('os_type')
            if timing_template:
                if timing_template == 'paranoid':
                    timing_template = '-T0'
                elif timing_template == 'sneaky':
                    timing_template = '-T1'
                elif timing_template == 'polite':
                    timing_template = '-T2'
                elif timing_template == 'normal':
                    timing_template = '-T3'
                elif timing_template == 'aggressive':
                    timing_template = '-T4'
                elif timing_template == 'insane':
                    timing_template = '-T5'

            
            if target:
                # check if target is valid ip address
                if not validate_ip_address(target):
                        flash("Invalid IP address format", "error")
                        return render_template("ip_protocol_scan.html",
                                    user=current_user,
                                    project_id=project_id,
                                    project_name=project_name,
                                    projects=all_projects,
                                    stored_data=get_all_ip_protocol_scans_for_project(project_id, current_user.id))
                else:
                    flash("Scan completed successfully", "success")
                
                # build nmap command based on os_type
                if os_type == 'mac':
                    nmap_command = ["sudo", "nmap", timing_template, "-sO", target]
                else:
                    nmap_command = ["nmap", timing_template, "-sO", target]
                result = subprocess.run(nmap_command, capture_output=True, text=True)
                scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # pattern for get scan info from nmap output
                total_hosts_scanned = get_total_scanned_host_by_its_pattern(result.stdout)
                host_up = get_total_up_host_by_its_pattern(result.stdout)
                total_scan_time = get_total_scanned_time_by_its_pattern(result.stdout)
                scan_blocks = get_two_scan_block_by_its_pattern(result.stdout)


                # check if no ip address found, if not, no reachable host found
                if host_up[0] == "0":
                    flash("No IP addresses found in the scan results", "error")
                    return redirect(url_for('views.ip_protocol_scan', project_id=project_id))

                # insert to ip_protocol_scan_summary and get scan_id
                scan_id = insert_to_ip_protocol_scan_summary(
                    scan_time,
                    total_hosts_scanned[0],  
                    host_up[0] ,                        
                    total_scan_time[0],          
                    timing_template
                )

                #extract ip address and latency from each scan scan block and insert to ip_protocol_scan
                for block in scan_blocks:
                    ip_match = get_ip_addresses_by_its_pattern(block)
                    latency_match = get_latency_by_its_pattern(block)
                    if ip_match:
                        #portocol_state_service_match = protocol_state_service_pattern.findall(block)
                        portocol_state_service_match = get_protocol_state_service_by_its_pattern(block)
                        for m in portocol_state_service_match:
                            insert_to_ip_protocol_scan(ip_match[0], latency_match[0], scan_id,
                                m[0], m[1], m[2], current_user.id, project_id)
                            
                return redirect(url_for('views.ip_protocol_scan', project_id=project_id))

                    
        # Initial page load or no resultsz
        stored_data = get_all_ip_protocol_scans_for_project(project_id, current_user.id)
        

        return render_template("ip_protocol_scan.html", 
                            user=current_user, 
                            project_id=project_id,
                            project_name=project_name,
                            projects=all_projects,
                            stored_data=stored_data)

    except Exception as e:
        print(f"Database error: {str(e)}")
        return render_template("ip_protocol_scan.html", 
                            error=f"Database error: {str(e)}", 
                            user=current_user,
                            )

# source ----------------- https://flask.palletsprojects.com/en/stable/quickstart/ -----------------
# source ----------------- https://www.datacamp.com/tutorial/python-subprocess ----------------
# source ----------------- https://www.index.dev/blog/python-database-error-handling-try-except ---------------

