import argparse
import os
import sqlite3
import hashlib
import time
import shutil
import zipfile
from tqdm import tqdm

# Create logs and backups directories if they don't exist
if not os.path.exists('logs'):
    os.makedirs('logs')
if not os.path.exists('backups'):
    os.makedirs('backups')

def create_database(database_name):
    connection = sqlite3.connect(database_name)
    cursor = connection.cursor()

    if 'combolist' in database_name:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS combolist_leaks (
                id INTEGER PRIMARY KEY,
                timestamp TIMESTAMP,
                hash TEXT,
                user TEXT,
                pass TEXT
            )
        ''')
    elif 'infostealer' in database_name:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS infostealer_leaks (
                id INTEGER PRIMARY KEY,
                timestamp TIMESTAMP,
                hash TEXT,
                url TEXT,
                user TEXT,
                pass TEXT
            )
        ''')
    connection.commit()
    connection.close()

def verify_file(file_path):
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return False
    return True

def calculate_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

def log_message(message, log_file_path='logs/script.log'):
    with open(log_file_path, 'a') as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
        log_file.flush()

def backup_database(database_name):
    timestamp = time.strftime('%Y-%m-%d_%H-%M-%S')
    backup_filename = f'backups/{database_name.split(".")[0]}_backup_{timestamp}.zip'

    try:
        # Create the backup in a work directory
        temp_backup_dir = f'temp_backup_{timestamp}'
        os.makedirs(temp_backup_dir)
        shutil.copy2(database_name, temp_backup_dir)
        backup_path = os.path.join(temp_backup_dir, database_name)

        # Create a zip file with the backup
        with zipfile.ZipFile(backup_filename, 'w', zipfile.ZIP_DEFLATED) as backup_zip:
            backup_zip.write(backup_path, os.path.basename(backup_path))

        # Clean up the work directory
        shutil.rmtree(temp_backup_dir)

        log_message(f"Created compressed backup: {backup_filename}")
    except Exception as e:
        log_message(f"Backup creation failed: {e}", 'logs/error.log')

def main():
    parser = argparse.ArgumentParser(description='Leak Database')
    parser.add_argument('--combolist', action='store_true', help='Process combolist file')
    parser.add_argument('--infostealer', action='store_true', help='Process infostealer file')
    parser.add_argument('file_path', type=str, help='Path to the input file')
    args = parser.parse_args()

    if args.combolist:
        database_name = 'combolists-leaks.sqlite'
        delimiter = ':' # Default delimiter for combolists
    elif args.infostealer:
        database_name = 'infostealer-leaks.sqlite'
        delimiter = ','  # Default delimiter for infostealer
    else:
        print("Error: You must specify either --combolist or --infostealer.")
        return

    log_message("=============Script started=============")

    if not verify_file(args.file_path):
        log_message(f"File verification failed for '{args.file_path}'", 'logs/error.log')
        return

    backup_database(database_name)  # Create a backup before making changes

    # Create or connect to the database
    create_database(database_name)
    connection = sqlite3.connect(database_name)
    cursor = connection.cursor()

    # Collect existing hashes
    if args.combolist:
        existing_hashes = set(hash[0] for hash in cursor.execute('SELECT hash FROM combolist_leaks').fetchall())
    elif args.infostealer:
        existing_hashes = set(hash[0] for hash in cursor.execute('SELECT hash FROM infostealer_leaks').fetchall())

    # Create the leaks_to_report file
    timestamp = time.strftime('%Y-%m-%d_%H-%M-%S')
    report_filename = f'leaks_to_report-{timestamp}.txt'
    report_file = open(report_filename, 'w')

    # Process the input file with tqdm progress bar
    with open(args.file_path, 'r') as input_file:
        total_lines = sum(1 for _ in input_file)
        input_file.seek(0)

        with tqdm(total=total_lines, unit='line') as progress_bar:
            for line in input_file:
                fields = line.strip().split(delimiter)

                if args.combolist and len(fields) == 2:
                    user, password = fields
                    hash_value = calculate_hash(user + password)

                    if hash_value not in existing_hashes:
                        cursor.execute('INSERT INTO combolist_leaks (timestamp, hash, user, pass) VALUES (?, ?, ?, ?)',
                                       (time.strftime('%Y-%m-%d %H:%M:%S'), hash_value, user, password))
                        log_message(f"Inserted new entry: {user}:{password}")
                        existing_hashes.add(hash_value)

                        connection.commit()

                        report_file.write(line)
                        report_file.flush()

                elif args.infostealer and len(fields) == 3:
                    url, user, password = fields
                    hash_value = calculate_hash(url + user + password)

                    if hash_value not in existing_hashes:
                        cursor.execute('INSERT INTO infostealer_leaks (timestamp, hash, url, user, pass) VALUES (?, ?, ?, ?, ?)',
                                       (time.strftime('%Y-%m-%d %H:%M:%S'), hash_value, url, user, password))
                        log_message(f"Inserted new entry: {url}:{user}:{password}")
                        existing_hashes.add(hash_value)

                        connection.commit()

                        report_file.write(line)
                        report_file.flush()

                else:
                    log_message(f"Invalid input for {'--combolist' if args.combolist else '--infostealer'}: {line}", 'logs/error.log')

                progress_bar.update(1)

    report_file.close()
    connection.close()

    log_message("=============Script finished=============\n")

if __name__ == '__main__':
    main()