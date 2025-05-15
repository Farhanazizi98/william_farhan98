from flask import Blueprint, redirect, url_for, flash
from flask_login import login_required, current_user
from . import get_db
import sqlite3

# Create the blueprint
delete = Blueprint("delete", __name__)

@delete.route("/delete-project/<int:project_id>", methods=["POST"])
@login_required
def delete_project(project_id):
    database = get_db()
    cursor = database.cursor()

    try:
        # Get project details before deleting
        cursor.execute("""
            SELECT name, scan_type 
            FROM projects 
            WHERE id = ? AND user_id = ?
        """, (project_id, current_user.id))
        project = cursor.fetchone()
        
        if not project:
            flash("Project not found", category="error")
            return redirect(url_for("views.home"))
        
        scan_type = project[1]

        try:
            # Start transaction
            cursor.execute("BEGIN")
            
            # Delete related scan data based on scan type
            if scan_type == 'ICMP':

                # First get all scan_ids for this project
                cursor.execute("""
                    SELECT DISTINCT scan_id 
                    FROM icmp_scan 
                    WHERE project_id = ? AND user_id = ?
                """, (project_id, current_user.id))
                scan_ids = [row[0] for row in cursor.fetchall()]
                
                # Delete from icmp_scan
                cursor.execute("DELETE FROM icmp_scan WHERE project_id = ?", (project_id,))
                
                # Delete from scan_summary
                if scan_ids:
                    cursor.execute("""
                        DELETE FROM icmp_scan_summary 
                        WHERE id IN ({})
                    """.format(','.join('?' * len(scan_ids))), scan_ids) # AI approch to delete the icmp scan summary
                    
            #delete the port scan
            elif scan_type == 'port_scan':

                cursor.execute("""
                    SELECT DISTINCT scan_id 
                    FROM TCP_UDP_SCAN 
                    WHERE project_id = ? AND user_id = ?
                """, (project_id, current_user.id))
                scan_ids = [row[0] for row in cursor.fetchall()]

                #delete the port scan
                cursor.execute("DELETE FROM TCP_UDP_SCAN WHERE project_id = ?", (project_id,))

                #delete the port scan summary
                if scan_ids:
                    cursor.execute("""
                        DELETE FROM TCP_UDP_scan_summary 
                        WHERE id IN ({})
                    """.format(','.join('?' * len(scan_ids))), scan_ids) # AI approch to delete the port scan summary


            elif scan_type == 'ip_protocol_scan':
                #delete the ip protocol scan
                cursor.execute("""
                    SELECT DISTINCT scan_id 
                    FROM IP_PROTOCOL_SCAN 
                    WHERE project_id = ? AND user_id = ?
                """, (project_id, current_user.id))
                scan_ids = [row[0] for row in cursor.fetchall()]

                #Delete the ip protocol scan
                cursor.execute("DELETE FROM IP_PROTOCOL_SCAN WHERE project_id = ?", (project_id,))

                #delete the ip protocol scan summary
                if scan_ids:
                    cursor.execute("""
                        DELETE FROM IP_PROTOCOL_SCAN_SUMMARY 
                        WHERE id IN ({})
                    """.format(','.join('?' * len(scan_ids))), scan_ids) # AI approch to delete the ip protocol scan summary

                
            
            # Delete the project
            cursor.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            
            # Get remaining projects and rename them sequentially
            cursor.execute("""
                SELECT id, name 
                FROM projects 
                WHERE user_id = ? AND scan_type = ? 
                ORDER BY created_at ASC
            """, (current_user.id, scan_type))
            
            remaining_projects = cursor.fetchall()
            
            # Update project names
            for index, (proj_id, _) in enumerate(remaining_projects, 1):
                new_name = f"Project {index}"
                cursor.execute("""
                    UPDATE projects 
                    SET name = ? 
                    WHERE id = ?
                """, (new_name, proj_id))
            
            # Commit transaction
            cursor.execute("COMMIT")
            database.commit()

            # Redirect based on scan type
            if scan_type == 'ICMP':
                return redirect(url_for("views.icmp_scan"))
            elif scan_type == 'port_scan':
                return redirect(url_for("views.tcp_udp_scan"))
            elif scan_type == 'ip_protocol_scan':
                return redirect(url_for("views.ip_protocol_scan"))
            
        except sqlite3.Error as e:
            cursor.execute("ROLLBACK")
            database.rollback()
            flash("Error deleting project", category="error")
        
    except Exception as e:
        flash("An error occurred", category="error")
    
    return redirect(url_for("views.home"))
                        

# source ----------------- https://docs.python.org/3/library/sqlite3.html ------------------