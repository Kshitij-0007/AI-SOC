import sqlite3
import os

db_path = r'C:\ai-soc\backend\data\ai_soc.db'
print(f'Database path: {db_path}')
print(f'Exists: {os.path.exists(db_path)}')

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# List all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print('\nTables:', len(tables))
for table in tables:
    table_name = table[0]
    cursor.execute(f'PRAGMA table_info({table_name})')
    columns = cursor.fetchall()
    print(f'\nTable: {table_name}')
    print(f'Columns: {len(columns)}')
    for col in columns:
        print(f'  - {col}')
    
    cursor.execute(f'SELECT COUNT(*) FROM {table_name}')
    count = cursor.fetchone()[0]
    print(f'Row count: {count}')

conn.close()