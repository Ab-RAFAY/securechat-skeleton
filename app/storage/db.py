"""
Simple MySQL schema init and helper functions. Uses mysql-connector-python.
Usage:
python -m app.storage.db --init
"""
import argparse
import mysql.connector
from pathlib import Path
import os
from hashlib import sha256


DB_CONFIG = {
    'host': os.environ.get('DB_HOST', '127.0.0.1'),
    'port': int(os.environ.get('DB_PORT', 3306)),
    'user': os.environ.get('DB_USER', 'scuser'),
    'password': os.environ.get('DB_PASS', 'scpass'),
    'database': os.environ.get('DB_NAME', 'securechat')
}


SCHEMA = '''
    CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255),
    username VARCHAR(100) UNIQUE,
    salt VARBINARY(16),
    pwd_hash CHAR(64)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
'''




def init_db():
    conn = mysql.connector.connect(
    host=DB_CONFIG['host'], user=DB_CONFIG['user'], password=DB_CONFIG['password']
    )
    cursor = conn.cursor()
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
    conn.commit()
    conn.close()


    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    for stmt in SCHEMA.split(';'):
        if stmt.strip():
            cursor.execute(stmt)
    conn.commit()
    conn.close()
    print('Initialized DB and created users table')




if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--init', action='store_true')
    args = p.parse_args()
    if args.init:
        init_db()