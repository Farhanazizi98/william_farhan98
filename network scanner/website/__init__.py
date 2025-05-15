from flask import Flask, g, redirect, url_for, request
from flask_login import LoginManager, current_user
import sqlite3 
import os
from.models import User

# Get the database path
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../database.db")

# Get the database connection
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.execute("PRAGMA foreign_keys = ON")  # Enable foreign key support
        db.row_factory = sqlite3.Row  

    return db

# Close the database connection
def close_db_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# Initialize the database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Create users table if it does not exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            firstName TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # Create projects table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at DATETIME NOT NULL,
            scan_type TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')


    # Create scan summary table first
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS icmp_scan_summary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time DATETIME NOT NULL,
            total_hosts_scanned INTEGER,
            host_up INTEGER,
            total_scan_time FLOAT,
            time_template TEXT NOT NULL
        )
    ''')

    # Create icmp_scan table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS icmp_scan (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip text(20) NOT NULL,
            latency text(20) NOT NULL,
            scan_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            project_id INTEGER NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES icmp_scan_summary(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )
    ''')

    

    # Create TCP_UDP_SCAN table if it doesn't exist
    cursor.execute("""CREATE TABLE IF NOT EXISTS TCP_UDP_scan_summary (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time DATETIME NOT NULL,
        total_scanned_hosts INTEGER,
        host_up INTEGER,
        total_scan_time FLOAT,
        port_range TEXT,
        time_template TEXT
    )
    """)

    # Create TCP_UDP_SCAN table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS TCP_UDP_SCAN (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            user_id INTEGER,
            target TEXT,
            port TEXT,
            state TEXT,
            service TEXT,
            scan_type TEXT,
            scan_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (project_id) REFERENCES projects(id),
            FOREIGN KEY (scan_id) REFERENCES TCP_UDP_scan_summary(id)
        )
    ''')

    # Create IP_PROTOCOL_SCAN table if it doesn't exist 
    cursor.execute("""CREATE TABLE IF NOT EXISTS IP_PROTOCOL_SCAN_SUMMARY (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time DATETIME NOT NULL,
        total_hosts_scanned INTEGER,
        host_up INTEGER,
        total_scan_time FLOAT,
        time_template TEXT NOT NULL
    )""")

    # Create IP_PROTOCOL_SCAN table if it doesn't exist 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS IP_PROTOCOL_SCAN (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip text(20) NOT NULL,
            latency text(20) NOT NULL,
            scan_id INTEGER NOT NULL,
            protocol TEXT,
            state TEXT,
            service TEXT,
            user_id INTEGER NOT NULL,
            project_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (project_id) REFERENCES projects(id),
            FOREIGN KEY (scan_id) REFERENCES IP_PROTOCOL_SCAN_SUMMARY(id)
        )
    ''')

    conn.commit()
    conn.close()

#init the login manager
login_manager = LoginManager()
login_manager.login_view = "auth.login"

#create the app
def create_app():
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE="database.db",
        SECRET_KEY = "mysecretkey"
    )

    login_manager.init_app(app)

    #import the views and auth blueprints
    from .views import views
    from .auth import auth
    from .delete import delete

    #register the blueprints
    app.register_blueprint(views, url_prefix="/")
    app.register_blueprint(auth, url_prefix="/auth")
    app.register_blueprint(delete, url_prefix="/")

    #load the user
    @login_manager.user_loader
    def load_user(user_id):
        database = get_db()
        cursor = database.cursor()
        cursor.execute("SELECT * From users where id= ?", (user_id,))
        row = cursor.fetchone()
        if row:
            return User(id=row[0], email=row[1], firstName=row[2], password=row[3])
        return None

    #prevent caching of all responses (AI approach)
    @app.after_request
    def add_header(response):
        # Prevent caching of all responses
        response.headers['Cache-Control'] = 'no-store'
        return response

    #check if the user is authenticated, (AI approach)
    @app.before_request
    def check_user_session():
        # Allow access to auth routes and static files
        if request.endpoint and (request.endpoint.startswith('auth.') or request.endpoint.startswith('static')): 
            return

        # Check if user is not authenticated
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))

    #close the database connection
    @app.teardown_appcontext
    def teardown_db(exception):
        close_db_connection(exception)

    return app

def init_app(app):
    init_db()


#source --------------- https://github.com/techwithtim/Flask-Web-App-Tutorial/tree/main/website ---------------


#source ---------------- https://flask.palletsprojects.com/en/stable/tutorial/database/ ----------------

#source ----------https://loadforge.com/guides/effective-caching-strategies-for-faster-flask-applications -------------

#source ------------ https://www.reddit.com/r/learnpython/comments/15404qk/sqlite_db_file_in_different_directory/ ------------
