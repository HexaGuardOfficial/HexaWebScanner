import sqlite3
import json
from datetime import datetime

class DatabaseManager:
    def __init__(self):
        self.db_name = "hexa_vuln_scanner.db"
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self._create_tables()

    def _create_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                email TEXT UNIQUE,
                password TEXT
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT,
                type TEXT,
                severity TEXT,
                description TEXT
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE,
                value TEXT,
                timestamp TEXT
            )
        ''')
        self.conn.commit()

    def get_cache(self, key: str) -> dict:
        """Get cached data by key"""
        try:
            self.cursor.execute('SELECT value, timestamp FROM cache WHERE key = ?', (key,))
            result = self.cursor.fetchone()
            if result:
                value, timestamp = result
                return {
                    'data': json.loads(value),
                    'timestamp': datetime.fromisoformat(timestamp)
                }
            return None
        except Exception as e:
            print(f"Error getting cache: {str(e)}")
            return None

    def set_cache(self, key: str, value: dict) -> bool:
        """Set cache data with key"""
        try:
            value_str = json.dumps(value['data'])
            timestamp = value['timestamp'].isoformat()
            
            self.cursor.execute('''
                INSERT OR REPLACE INTO cache (key, value, timestamp)
                VALUES (?, ?, ?)
            ''', (key, value_str, timestamp))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error setting cache: {str(e)}")
            return False

    def save_user(self, username, email, password):
        self.cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, password))
        self.conn.commit()

    def get_user(self, username):
        self.cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        return self.cursor.fetchone()

    def save_owasp_results(self, target_url, vulnerabilities):
        for vuln in vulnerabilities:
            self.cursor.execute('INSERT INTO vulnerabilities (target_url, type, severity, description) VALUES (?, ?, ?, ?)', 
                              (target_url, vuln['type'], vuln['severity'], vuln['description']))
        self.conn.commit()

    def save_cve_results(self, target_url, vulnerabilities):
        for vuln in vulnerabilities:
            self.cursor.execute('INSERT INTO vulnerabilities (target_url, type, severity, description) VALUES (?, ?, ?, ?)', 
                              (target_url, vuln['type'], vuln['severity'], vuln['description']))
        self.conn.commit()

    def save_zeroday_results(self, target_url, vulnerabilities):
        for vuln in vulnerabilities:
            self.cursor.execute('INSERT INTO vulnerabilities (target_url, type, severity, description) VALUES (?, ?, ?, ?)', 
                              (target_url, vuln['type'], vuln['severity'], vuln['description']))
        self.conn.commit()

    def get_vulnerabilities(self, target_url):
        self.cursor.execute('SELECT * FROM vulnerabilities WHERE target_url = ?', (target_url,))
        return self.cursor.fetchall()

    def get_all_users(self):
        self.cursor.execute('SELECT * FROM users')
        return self.cursor.fetchall()

    def get_all_logs(self):
        self.cursor.execute('SELECT * FROM vulnerabilities')
        return self.cursor.fetchall()