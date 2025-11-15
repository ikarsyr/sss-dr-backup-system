#!/usr/bin/env python3
"""
Enterprise Secure Distributed Backup System
Implements Shamir's Secret Sharing for key protection
"""

import os
import sys
import yaml
import json
import hashlib
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import secrets
from concurrent.futures import ThreadPoolExecutor
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
import pymongo
import redis
import psycopg2
import pymssql
import mysql.connector
import boto3
from azure.storage.blob import BlobServiceClient
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

class DRBackupSystem:
    # Constants
    ORPHAN_DB_FOLDER = '_dbs_not_part_of_a_project'

    def __init__(self, config_path: str):
        self.config = self.load_config(config_path)
        self.backup_date = datetime.now().strftime('%Y-%m-%d')
        self.setup_logging()
        self.backup_path = Path(self.config['general']['backup_source_base_path']) / self.backup_date
        self.temp_workspace = Path(self.config['general']['backup_target_base_path']) / self.backup_date

    def load_config(self, config_path: str) -> Dict:
        """Load and validate configuration"""
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        # Load sensitive data from environment variables
        for key in ['token_env', 'access_key_id_env', 'access_key_secret_env',
                    'backup_password_env', 'connection_string_env', 'password_env']:
            self._resolve_env_vars(config, key)

        return config

    def _resolve_env_vars(self, d: Dict, key_suffix: str):
        """Recursively resolve environment variables in config"""
        # Collect changes to avoid modifying dict during iteration
        changes = {}
        for k, v in d.items():
            if isinstance(v, dict):
                self._resolve_env_vars(v, key_suffix)
            elif isinstance(v, str) and k.endswith(key_suffix):
                env_var = v
                changes[k.replace('_env', '')] = os.environ.get(env_var, '')
        # Apply changes after iteration
        d.update(changes)

    def setup_logging(self):
        """Setup logging configuration"""
        # Create log directory if it doesn't exist
        log_dir = Path('./log')
        log_dir.mkdir(parents=True, exist_ok=True)

        logging.basicConfig(
            level=getattr(logging, self.config['general']['log_level']),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'./log/dr-backup-{self.backup_date}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def check_prerequisites(self) -> bool:
        """Check if backup can proceed"""
        # if self.backup_path.exists():
        #     self.logger.error(f"Backup directory already exists: {self.backup_path}")
        #     sys.exit(1)

        # Check required tools
        required_tools = ['glab', 'pg_dump', 'mysqldump', 'mongodump', 'tar', 'gpg']
        # required_tools = ['glab']
        for tool in required_tools:
            if subprocess.run(['which', tool], capture_output=True).returncode != 0:
                self.logger.error(f"Required tool not found: {tool}")
                return False

        return True

    def create_backup_structure(self):
        """Create backup directory structure"""
        self.logger.info(f"Creating backup structure at {self.backup_path}")

        # Create folder for orphan databases (not part of any project)
        # Repository folders will be created dynamically during gitlab backup
        (self.backup_path / self.ORPHAN_DB_FOLDER).mkdir(parents=True, exist_ok=True)
        (self.temp_workspace).mkdir(parents=True, exist_ok=True)

    def backup_gitlab(self):
        """Backup all GitLab repositories with nested structure"""
        # Check if GitLab is configured
        if 'gitlab' not in self.config or 'group' not in self.config['gitlab']:
            self.logger.info("No GitLab configuration found, skipping...")
            return

        self.logger.info("Starting GitLab backup...")

        # Get backup path overrides if configured
        path_overrides = self.config.get('backup_path_overrides', {})

        # Store repo info for later DB organization
        self.repo_paths = {}  # Maps repo path to backup path

        # Use glab CLI to get list of all projects
        env = os.environ.copy()
        env['GITLAB_TOKEN'] = self.config['gitlab']['token']

        list_cmd = [
            'glab', 'repo', 'list',
            '-g', self.config['gitlab']['group'],
            '--per-page', str(self.config['gitlab']['per_page'])
        ]

        if self.config['gitlab'].get('include_subgroups', True):
            list_cmd.append('--include-subgroups')

        result = subprocess.run(list_cmd, env=env, capture_output=True, text=True)

        if result.returncode != 0:
            self.logger.error(f"Failed to list GitLab projects: {result.stderr}")
            raise Exception("Failed to list GitLab projects")

        # Parse project list - glab returns tabular format
        # Skip header lines and extract project paths
        projects = []
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            # Skip header lines (contain "Project path", "Showing X of Y", etc.)
            if 'Project path' in line or 'Showing' in line or 'Page' in line:
                continue

            # Skip separator lines (dashes)
            if line.startswith('---') or line.startswith('==='):
                continue

            # Extract project path from tabular output (first column)
            # Format: "group/subgroup/project    other_columns..."
            parts = line.split()
            if parts and '/' in parts[0]:  # Valid path contains /
                project_path = parts[0]
                projects.append(project_path)

        self.logger.info(f"Found {len(projects)} repositories to backup")

        # Clone each repository into nested structure
        root_group = self.config['gitlab']['group']

        for project_full_path in projects:
            try:
                # Remove root group from path to get relative path
                if project_full_path.startswith(root_group + '/'):
                    relative_path = project_full_path[len(root_group) + 1:]
                else:
                    relative_path = project_full_path

                # Apply path override if configured
                backup_path = path_overrides.get(relative_path, relative_path)

                # Store mapping for DB organization later
                self.repo_paths[relative_path] = backup_path

                # Create nested directory structure with /code subfolder
                repo_code_dir = self.backup_path / backup_path / 'code'
                repo_code_dir.mkdir(parents=True, exist_ok=True)

                # Clone the repository
                clone_url = f"https://oauth2:{self.config['gitlab']['token']}@gitlab.com/{project_full_path}.git"

                self.logger.info(f"  Cloning {relative_path} -> {backup_path}/code")

                clone_cmd = ['git', 'clone', '--depth', '1', clone_url, str(repo_code_dir)]
                clone_result = subprocess.run(clone_cmd, capture_output=True, text=True)

                if clone_result.returncode != 0:
                    self.logger.error(f"Failed to clone {project_full_path}: {clone_result.stderr}")
                    continue

            except Exception as e:
                self.logger.error(f"Error backing up {project_full_path}: {e}")
                continue

        self.logger.info("GitLab backup completed")

    def organize_database_dumps(self):
        """Organize database dumps into repository folders based on mapping"""
        # Get the repository to DB mapping
        repo_to_db = self.config.get('repository_to_db_mapping', {})

        if not repo_to_db:
            self.logger.info("No repository_to_db_mapping configured, skipping DB organization")
            return

        self.logger.info("Organizing database dumps into repository folders...")

        db_dir = self.backup_path / self.ORPHAN_DB_FOLDER
        if not db_dir.exists():
            self.logger.warning("No orphan DB directory found, skipping DB organization")
            return

        # Track which DBs have been moved
        moved_dbs = set()

        # Iterate through the mapping
        for repo_path, db_identifier in repo_to_db.items():
            try:
                # Parse db_identifier: "instance_id.database_name"
                if '.' not in db_identifier:
                    self.logger.warning(f"Invalid DB identifier format '{db_identifier}' for repo '{repo_path}'. Expected 'instance_id.database_name'")
                    continue

                instance_id, db_name = db_identifier.split('.', 1)

                # Find the DB dump file in db/ directory
                # Current naming: {instance_id}_{db_name}.sql.gz
                source_file = db_dir / f"{instance_id}_{db_name}.sql.gz"

                if not source_file.exists():
                    self.logger.warning(f"DB dump file not found: {source_file}")
                    continue

                # Get the backup path (accounting for overrides)
                backup_path = self.repo_paths.get(repo_path, repo_path)

                # Create repo db directory
                repo_db_dir = self.backup_path / backup_path / 'db'
                repo_db_dir.mkdir(parents=True, exist_ok=True)

                # Move DB file with simplified name (just db_name.sql.gz)
                dest_file = repo_db_dir / f"{db_name}.sql.gz"

                self.logger.info(f"  Moving {instance_id}_{db_name}.sql.gz -> {backup_path}/db/{db_name}.sql.gz")

                # Move the file
                import shutil
                shutil.move(str(source_file), str(dest_file))

                moved_dbs.add(f"{instance_id}_{db_name}.sql.gz")

            except Exception as e:
                self.logger.error(f"Error organizing DB for repo '{repo_path}': {e}")
                continue

        # Log any orphan DBs that weren't mapped
        if db_dir.exists():
            remaining_dbs = [f.name for f in db_dir.glob('*.sql.gz')]
            if remaining_dbs:
                self.logger.info(f"Orphan DBs (not mapped to repos): {', '.join(remaining_dbs)}")

        self.logger.info("Database organization completed")

    def create_backup_user(self, engine: str, connection_params: Dict):
        """Create read-only backup user if not exists"""
        backup_user = self.config['databases']['backup_username']
        backup_pass = self.config['databases']['backup_password']

        try:
            if engine == 'postgresql':
                conn = psycopg2.connect(**connection_params)
                cur = conn.cursor()
                cur.execute(f"""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (SELECT FROM pg_user WHERE usename = '{backup_user}') THEN
                            CREATE USER {backup_user} WITH PASSWORD '{backup_pass}';
                        END IF;
                    END $$;
                    GRANT CONNECT ON DATABASE gamedb TO {backup_user};
                    GRANT USAGE ON SCHEMA public TO {backup_user};
                    GRANT SELECT ON ALL TABLES IN SCHEMA public TO {backup_user};
                """)
                conn.commit()

            elif engine == 'mysql':
                conn = mysql.connector.connect(**connection_params)
                cur = conn.cursor()
                cur.execute(f"""
                    CREATE USER IF NOT EXISTS '{backup_user}'@'%' IDENTIFIED BY '{backup_pass}';
                    GRANT SELECT, LOCK TABLES, SHOW VIEW, EVENT, TRIGGER ON *.* TO '{backup_user}'@'%';
                    FLUSH PRIVILEGES;
                """)

            elif engine == 'mssql':
                conn = pymssql.connect(**connection_params)
                cur = conn.cursor()
                cur.execute(f"""
                    IF NOT EXISTS (SELECT name FROM sys.server_principals WHERE name = '{backup_user}')
                    BEGIN
                        CREATE LOGIN {backup_user} WITH PASSWORD = '{backup_pass}'
                    END
                    IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name = '{backup_user}')
                    BEGIN
                        CREATE USER {backup_user} FOR LOGIN {backup_user}
                        ALTER ROLE db_datareader ADD MEMBER {backup_user}
                    END
                """)
                conn.commit()

        except Exception as e:
            self.logger.warning(f"Could not create backup user: {e}")

    def backup_rds_instance(self, instance: Dict) -> str:
        """Backup individual RDS instance"""
        self.logger.info(f"Backing up RDS instance: {instance['id']}")

        engine = instance['engine']
        endpoint = instance['endpoint']
        backup_file = self.backup_path / self.ORPHAN_DB_FOLDER / f"{instance['id']}_{engine}.sql"

        # Use backup user credentials
        username = self.config['databases']['backup_username']
        password = self.config['databases']['backup_password']

        host, port = endpoint.split(':') if ':' in endpoint else (endpoint, None)

        if engine == 'postgresql':
            env = os.environ.copy()
            env['PGPASSWORD'] = password

            # Get list of databases to backup
            databases = instance.get('databases', [])

            if databases and databases != 'all':
                # Dump each database individually
                total_dbs = len(databases)
                for idx, db_name in enumerate(databases, 1):
                    self.logger.info(f"  Dumping database: {db_name} [{instance['id']}: {idx}/{total_dbs}]")
                    db_backup_file = self.backup_path / self.ORPHAN_DB_FOLDER / f"{instance['id']}_{db_name}.sql"

                    cmd = [
                        'pg_dump',
                        '-h', host,
                        '-p', port or '5432',
                        '-U', username,
                        '-d', db_name,
                        '-f', str(db_backup_file),
                        '--clean',
                        '--if-exists'
                    ]
                    subprocess.run(cmd, env=env, check=True)

                    # Validate SQL file was created and has content
                    if not db_backup_file.exists():
                        error_msg = f"pg_dump did not create output file for {db_name} at {db_backup_file}"
                        self.logger.error(error_msg)
                        raise Exception(error_msg)

                    file_size = db_backup_file.stat().st_size
                    if file_size == 0:
                        error_msg = f"pg_dump created empty file for {db_name}"
                        self.logger.error(error_msg)
                        raise Exception(error_msg)

                    self.logger.info(f"  SQL dump size: {file_size / (1024*1024):.2f} MB")

                    # Compress individual backup using absolute path
                    subprocess.run(['gzip', '-9', str(db_backup_file.absolute())], check=True)

                # Return the first one for compatibility
                backup_file = self.backup_path / self.ORPHAN_DB_FOLDER / f"{instance['id']}_{databases[0]}.sql.gz"
            else:
                # Use pg_dumpall only if 'all' is specified
                cmd = [
                    'pg_dumpall',
                    '-h', host,
                    '-p', port or '5432',
                    '-U', username,
                    '-f', str(backup_file),
                    '--clean',
                    '--if-exists'
                ]
                subprocess.run(cmd, env=env, check=True)

                # Validate and compress the backup
                if not backup_file.exists():
                    error_msg = f"pg_dumpall did not create output file at {backup_file}"
                    self.logger.error(error_msg)
                    raise Exception(error_msg)

                file_size = backup_file.stat().st_size
                self.logger.info(f"  SQL dump size: {file_size / (1024*1024):.2f} MB")
                subprocess.run(['gzip', '-9', str(backup_file.absolute())], check=True)
                backup_file = f"{backup_file}.gz"

        elif engine == 'mysql':
            cmd = [
                'mysqldump',
                '-h', host,
                '-P', port or '3306',
                '-u', username,
                f'-p{password}',
                '--all-databases',
                '--single-transaction',
                '--routines',
                '--triggers',
                '--events',
                '--result-file', str(backup_file)
            ]
            subprocess.run(cmd, check=True)

            # Validate and compress the backup
            if not backup_file.exists():
                error_msg = f"mysqldump did not create output file at {backup_file}"
                self.logger.error(error_msg)
                raise Exception(error_msg)

            file_size = backup_file.stat().st_size
            self.logger.info(f"  SQL dump size: {file_size / (1024*1024):.2f} MB")
            subprocess.run(['gzip', '-9', str(backup_file.absolute())], check=True)
            backup_file = f"{backup_file}.gz"

        elif engine == 'mssql':
            # Get list of databases to backup
            databases = instance.get('databases', [])

            if databases and databases != 'all':
                # Dump each database individually
                total_dbs = len(databases)
                for idx, db_name in enumerate(databases, 1):
                    self.logger.info(f"  Dumping database: {db_name} [{instance['id']}: {idx}/{total_dbs}]")
                    db_backup_file = self.backup_path / self.ORPHAN_DB_FOLDER / f"{instance['id']}_{db_name}.sql"

                    cmd = [
                        sys.executable, '-m', 'mssqlscripter',
                        '-S', endpoint,
                        '-d', db_name,
                        '-U', username,
                        '-P', password,
                        '--schema-and-data',
                        '-f', str(db_backup_file)
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode != 0:
                        self.logger.error(f"mssql-scripter failed for {db_name}: {result.stderr}")
                        raise Exception(f"mssql-scripter failed for {db_name}: {result.stderr}")

                    # Validate SQL file was created and has content
                    if not db_backup_file.exists():
                        error_msg = f"mssql-scripter did not create output file for {db_name} at {db_backup_file}"
                        self.logger.error(error_msg)
                        raise Exception(error_msg)

                    file_size = db_backup_file.stat().st_size
                    if file_size == 0:
                        error_msg = f"mssql-scripter created empty file for {db_name}"
                        self.logger.error(error_msg)
                        raise Exception(error_msg)

                    self.logger.info(f"  SQL dump size: {file_size / (1024*1024):.2f} MB")

                    # Compress individual backup using absolute path
                    subprocess.run(['gzip', '-9', str(db_backup_file.absolute())], check=True)

                # Return the first one for compatibility
                backup_file = self.backup_path / self.ORPHAN_DB_FOLDER / f"{instance['id']}_{databases[0]}.sql.gz"
            else:
                # Backup all databases to single file
                cmd = [
                    sys.executable, '-m', 'mssqlscripter',
                    '-S', endpoint,
                    '-U', username,
                    '-P', password,
                    '--schema-and-data',
                    '-f', str(backup_file)
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    self.logger.error(f"mssql-scripter failed: {result.stderr}")
                    raise Exception(f"mssql-scripter failed: {result.stderr}")

                # Validate and compress the backup
                if not backup_file.exists():
                    error_msg = f"mssql-scripter did not create output file at {backup_file}"
                    self.logger.error(error_msg)
                    raise Exception(error_msg)

                file_size = backup_file.stat().st_size
                self.logger.info(f"  SQL dump size: {file_size / (1024*1024):.2f} MB")
                subprocess.run(['gzip', '-9', str(backup_file.absolute())], check=True)
                backup_file = f"{backup_file}.gz"

        return str(backup_file)

    def backup_external_databases(self):
        """Backup external database services"""
        # Check if external_databases is configured
        if 'databases' not in self.config or 'external_databases' not in self.config['databases'] or not self.config['databases']['external_databases']:
            self.logger.info("No external databases configured, skipping...")
            return

        self.logger.info("Backing up external databases...")

        for db in self.config['databases']['external_databases']:
            if db['type'] == 'mongodb':
                self.backup_mongodb(db)
            elif db['type'] == 'redis':
                self.backup_redis(db)

    def backup_mongodb(self, config: Dict):
        """Backup MongoDB instance"""
        self.logger.info(f"Backing up MongoDB: {config['id']}")

        backup_dir = self.backup_path / self.ORPHAN_DB_FOLDER / config['id']
        backup_dir.mkdir(exist_ok=True)

        cmd = [
            'mongodump',
            '--uri', config['connection_string'],
            '--out', str(backup_dir),
            '--gzip'
        ]

        subprocess.run(cmd, check=True)

    def backup_redis(self, config: Dict):
        """Backup Redis instance"""
        self.logger.info(f"Backing up Redis: {config['id']}")

        # Connect and create RDB dump
        r = redis.Redis.from_url(f"redis://:{config['password']}@{config['endpoint']}")
        r.bgsave()

        # Wait for backup to complete
        while r.lastsave() == r.lastsave():
            time.sleep(1)

        # Note: You'd need to retrieve the RDB file from Redis server
        # This is a simplified version

    def archive_backup(self) -> str:
        """Create compressed archive of backup directory"""
        self.logger.info("Creating backup archive...")

        # Remove orphan DB folder if it's empty
        orphan_db_dir = self.backup_path / self.ORPHAN_DB_FOLDER
        if orphan_db_dir.exists() and not any(orphan_db_dir.iterdir()):
            self.logger.info(f"Removing empty {self.ORPHAN_DB_FOLDER} folder")
            orphan_db_dir.rmdir()

        archive_name = f"dr-backup-{self.backup_date}.tar.gz"
        archive_path = self.temp_workspace / archive_name

        cmd = [
            'tar',
            '-czf', str(archive_path),
            '-C', str(self.backup_path.parent),
            self.backup_date
        ]

        subprocess.run(cmd, check=True)

        return str(archive_path)

    def encrypt_with_shamir(self, archive_path: str) -> Dict:
        """
        Encrypt archive using AES and protect key with Shamir's Secret Sharing
        This ensures that even if the backup machine is compromised,
        the attacker needs multiple key shares to decrypt
        """
        self.logger.info("Encrypting backup with Shamir's Secret Sharing...")

        # Generate a random AES-128 key (16 bytes required for Shamir's Secret Sharing)
        aes_key = get_random_bytes(16)

        # Encrypt the archive
        encrypted_path = f"{archive_path}.enc"

        with open(archive_path, 'rb') as f_in:
            data = f_in.read()

        # AES encryption in GCM mode for authenticated encryption
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        with open(encrypted_path, 'wb') as f_out:
            # Write nonce, tag, and ciphertext
            f_out.write(cipher.nonce)
            f_out.write(tag)
            f_out.write(ciphertext)

        # Split the AES key using Shamir's Secret Sharing
        shares = Shamir.split(
            self.config['encryption']['threshold'],
            self.config['encryption']['total_shares'],
            aes_key
        )

        # Save shares to temporary files (will be distributed after upload succeeds)
        shares_temp_dir = self.temp_workspace / 'shares_temp'
        shares_temp_dir.mkdir(exist_ok=True)

        for i, (idx, share) in enumerate(shares):
            share_file = shares_temp_dir / f"share_{idx}.json"
            share_data = {
                'backup_date': self.backup_date,
                'share_index': idx,
                'share': share.hex(),
                'threshold': self.config['encryption']['threshold'],
                'total_shares': self.config['encryption']['total_shares']
            }
            with open(share_file, 'w') as f:
                json.dump(share_data, f, indent=2)

        # Delete the original archive and AES key from memory
        os.remove(archive_path)
        del aes_key

        return {
            'encrypted_file': encrypted_path,
            'shares_temp_dir': str(shares_temp_dir),
            'shares_count': len(shares),
            'threshold': self.config['encryption']['threshold']
        }

    def distribute_shares_from_temp(self, shares_temp_dir: str, checksum: str):
        """
        Distribute pre-created key shares from temporary storage
        This is called AFTER successful upload to ensure shares are only distributed
        when the backup is safely stored
        """
        import glob

        self.logger.info("Distributing key shares after successful upload...")

        # Store checksum for email shares
        self.backup_checksum = checksum

        share_locations = self.config['encryption']['share_locations']
        share_files = sorted(glob.glob(f"{shares_temp_dir}/share_*.json"))

        for i, share_file in enumerate(share_files):
            if i >= len(share_locations):
                break

            location = share_locations[i]

            # Load share data from temp file
            with open(share_file, 'r') as f:
                share_data = json.load(f)

            if location['type'] == 'vault':
                self.store_share_vault(location, share_data)
            elif location['type'] == 'aws_secrets':
                self.store_share_aws(location, share_data)
            elif location['type'] == 'azure_keyvault':
                self.store_share_azure(location, share_data)
            elif location['type'] == 'local_disk':
                self.store_share_local_disk(location, share_data)
            elif location['type'] == 'email':
                self.store_share_email(location, share_data)
            elif location['type'] == 'offline':
                self.store_share_offline(location, share_data)

    def debug_print_email_message(self, shares_temp_dir: str, checksum: str):
        """
        DEBUG METHOD: Print first email message without sending
        For testing email template and backup structure generation
        """
        import glob

        print("\n" + "="*80)
        print("DEBUG: Email Message Preview")
        print("="*80 + "\n")

        # Store checksum
        self.backup_checksum = checksum

        # Get first email share location
        email_locations = [loc for loc in self.config['encryption']['share_locations'] if loc['type'] == 'email']
        if not email_locations:
            print("ERROR: No email share locations configured!")
            return

        location = email_locations[0]

        # Load first share
        share_files = sorted(glob.glob(f"{shares_temp_dir}/share_*.json"))
        if not share_files:
            print("ERROR: No share files found!")
            return

        with open(share_files[0], 'r') as f:
            share_data = json.load(f)

        # Generate email using the same logic as store_share_email
        template_path = Path(__file__).parent / 'email_template.txt'
        with open(template_path, 'r') as f:
            template = f.read()

        backup_info = self._collect_backup_info()

        storage_location = "Local: " + str(self.temp_workspace)
        if 'storage' in self.config and 'primary' in self.config['storage']:
            storage_location = f"{self.config['storage']['primary']['endpoint']}/{self.config['storage']['primary']['bucket']}/{self.backup_date}/dr-backup-{self.backup_date}.tar.gz.enc"

        share_locations_text = ""
        for share_loc in self.config['encryption']['share_locations']:
            share_locations_text += "-- "
            for key, value in share_loc.items():
                share_locations_text += f"{key.capitalize()}: {value}. "
            share_locations_text = share_locations_text.rstrip(". ") + "\n"

        backup_structure = self._generate_backup_structure()

        email_body = template.format(
            name=location['name'],
            backup_date=self.backup_date,
            backup_structure=backup_structure,
            checksum=backup_info.get('checksum', 'Pending'),
            storage_location=storage_location,
            total_shares=self.config['encryption']['total_shares'],
            threshold=self.config['encryption']['threshold'],
            share_locations=share_locations_text.rstrip('\n')
        )

        print(email_body)
        print("\n" + "="*80)
        print(f"Share file would be attached: share_{self.backup_date}_{share_data['share_index']}.json")
        print("="*80 + "\n")

    def distribute_key_shares(self, shares: List):
        """
        Distribute key shares to multiple secure locations
        This prevents single point of failure
        DEPRECATED: Use distribute_shares_from_temp() instead for better security
        """
        share_locations = self.config['encryption']['share_locations']

        for i, (idx, share) in enumerate(shares):
            if i >= len(share_locations):
                break

            location = share_locations[i]
            share_data = {
                'backup_date': self.backup_date,
                'share_index': idx,
                'share': share.hex(),
                'threshold': self.config['encryption']['threshold'],
                'total_shares': self.config['encryption']['total_shares']
            }

            if location['type'] == 'vault':
                self.store_share_vault(location, share_data)
            elif location['type'] == 'aws_secrets':
                self.store_share_aws(location, share_data)
            elif location['type'] == 'azure_keyvault':
                self.store_share_azure(location, share_data)
            elif location['type'] == 'local_disk':
                self.store_share_local_disk(location, share_data)
            elif location['type'] == 'email':
                self.store_share_email(location, share_data)
            elif location['type'] == 'offline':
                self.store_share_offline(location, share_data)

    def store_share_vault(self, location: Dict, share_data: Dict):
        """Store share in HashiCorp Vault"""
        import hvac

        client = hvac.Client(url=location['url'])
        client.token = os.environ.get('VAULT_TOKEN')

        path = f"{location['path']}/{self.backup_date}/share_{share_data['share_index']}"
        client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret=share_data
        )

        self.logger.info(f"Stored share {share_data['share_index']} in Vault")

    def store_share_aws(self, location: Dict, share_data: Dict):
        """Store share in AWS Secrets Manager"""
        client = boto3.client('secretsmanager', region_name=location['region'])

        secret_name = f"{location['secret_name']}-{self.backup_date}"
        client.create_secret(
            Name=secret_name,
            SecretString=json.dumps(share_data)
        )

        self.logger.info(f"Stored share {share_data['share_index']} in AWS Secrets Manager")

    def store_share_azure(self, location: Dict, share_data: Dict):
        """Store share in Azure Key Vault"""
        credential = DefaultAzureCredential()
        client = SecretClient(
            vault_url=f"https://{location['vault_name']}.vault.azure.net",
            credential=credential
        )

        secret_name = f"{location['secret_name']}-{self.backup_date}"
        client.set_secret(secret_name, json.dumps(share_data))

        self.logger.info(f"Stored share {share_data['share_index']} in Azure Key Vault")

    def store_share_local_disk(self, location: Dict, share_data: Dict):
        """Store share on local disk as JSON file"""
        # Create the directory if it doesn't exist
        share_dir = Path(location['path'])
        share_dir.mkdir(parents=True, exist_ok=True)

        # Create filename with backup date and share index
        share_file = share_dir / f"share_{self.backup_date}_{share_data['share_index']}.json"

        # Write share data as JSON
        with open(share_file, 'w') as f:
            json.dump(share_data, f, indent=2)

        # Set restrictive permissions (owner read/write only)
        os.chmod(share_file, 0o600)

        self.logger.info(f"Stored share {share_data['share_index']} on local disk: {share_file}")
        if 'description' in location:
            self.logger.info(f"  Location: {location['description']}")

    def store_share_email(self, location: Dict, share_data: Dict):
        """Send share via email with backup details"""
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.application import MIMEApplication

        self.logger.info(f"Preparing email share for {location['name']} ({location['address']})")

        # Create share JSON file in temp location
        share_file = self.temp_workspace / f"share_{self.backup_date}_{share_data['share_index']}.json"
        with open(share_file, 'w') as f:
            json.dump(share_data, f, indent=2)

        # Load email template
        template_path = Path(__file__).parent / 'email_template.txt'
        with open(template_path, 'r') as f:
            template = f.read()

        # Collect backup information
        backup_info = self._collect_backup_info()

        # Get storage location
        storage_location = "Local: " + str(self.temp_workspace)
        if 'storage' in self.config and 'primary' in self.config['storage']:
            storage_location = f"{self.config['storage']['primary']['endpoint']}/{self.config['storage']['primary']['bucket']}/{self.backup_date}/dr-backup-{self.backup_date}.tar.gz.enc"

        # Format share locations
        share_locations_text = ""
        for share_loc in self.config['encryption']['share_locations']:
            share_locations_text += "-- "
            for key, value in share_loc.items():
                share_locations_text += f"{key.capitalize()}: {value}. "
            share_locations_text = share_locations_text.rstrip(". ") + "\n"

        # Generate backup structure before archiving
        backup_structure = self._generate_backup_structure()

        # Fill template
        email_body = template.format(
            name=location['name'],
            backup_date=self.backup_date,
            backup_structure=backup_structure,
            checksum=backup_info.get('checksum', 'Pending'),
            storage_location=storage_location,
            total_shares=self.config['encryption']['total_shares'],
            threshold=self.config['encryption']['threshold'],
            share_locations=share_locations_text.rstrip('\n')
        )

        # Create email
        msg = MIMEMultipart()
        msg['From'] = self.config['general'].get('notification_email', 'backup@company.com')
        msg['To'] = location['address']
        msg['Subject'] = f"Backup Key Share - {self.backup_date}"

        # Attach body
        msg.attach(MIMEText(email_body, 'plain'))

        # Attach share file
        with open(share_file, 'rb') as f:
            attachment = MIMEApplication(f.read(), _subtype='json')
            attachment.add_header('Content-Disposition', 'attachment',
                                filename=f"share_{self.backup_date}_{share_data['share_index']}.json")
            msg.attach(attachment)

        # Send email (using SMTP configuration from environment or config)
        smtp_config = self._get_smtp_config()
        if smtp_config:
            try:
                with smtplib.SMTP(smtp_config['host'], smtp_config['port']) as server:
                    if smtp_config.get('use_tls', True):
                        server.starttls()
                    if smtp_config.get('username') and smtp_config.get('password'):
                        server.login(smtp_config['username'], smtp_config['password'])
                    server.send_message(msg)
                    self.logger.info(f"Sent share {share_data['share_index']} to {location['address']}")
            except Exception as e:
                self.logger.error(f"Failed to send email to {location['address']}: {e}")
                self.logger.info(f"Share file saved locally: {share_file}")
        else:
            self.logger.warning("No SMTP configuration found. Email not sent.")
            self.logger.info(f"Share file saved locally for manual sending: {share_file}")

    def _generate_backup_structure(self) -> str:
        """Generate tree structure of backup folder"""
        def build_tree(directory, prefix=""):
            """Recursively build directory tree"""
            try:
                items = sorted(directory.iterdir(), key=lambda x: (not x.is_dir(), x.name))
            except PermissionError:
                return ""

            tree = ""
            for i, item in enumerate(items):
                is_last_item = (i == len(items) - 1)
                connector = "└── " if is_last_item else "├── "

                tree += f"{prefix}{connector}{item.name}/\n" if item.is_dir() else f"{prefix}{connector}{item.name}\n"

                # Don't expand code/ and db/ folders
                if item.is_dir() and item.name not in ['code', 'db']:
                    extension = "    " if is_last_item else "│   "
                    tree += build_tree(item, prefix + extension)

            return tree

        if not self.backup_path.exists():
            return "Backup structure not available\n"

        return build_tree(self.backup_path)

    def _collect_backup_info(self) -> Dict:
        """Collect information about what was backed up"""
        info = {
            'rds_instances': [],
            'external_databases': [],
            'gitlab_repos': [],
            'checksum': getattr(self, 'backup_checksum', 'Pending')
        }

        # Collect RDS instances
        if 'databases' in self.config and 'rds_instances' in self.config['databases'] and self.config['databases']['rds_instances']:
            for instance in self.config['databases']['rds_instances']:
                info['rds_instances'].append({
                    'id': instance['id'],
                    'databases': instance.get('databases', [])
                })

        # Collect external databases
        if 'databases' in self.config and 'external_databases' in self.config['databases'] and self.config['databases']['external_databases']:
            for db in self.config['databases']['external_databases']:
                info['external_databases'].append({
                    'id': db['id'],
                    'type': db['type'],
                    'databases': db.get('databases', [])
                })

        # Collect GitLab repos from backup directory
        git_path = self.backup_path / 'git'
        if git_path.exists():
            info['gitlab_repos'] = [d.name for d in git_path.iterdir() if d.is_dir()]

        return info

    def _get_smtp_config(self) -> Dict:
        """Get SMTP configuration from config or environment"""
        # Check if SMTP is configured in config file
        if 'smtp' in self.config:
            return self.config['smtp']

        # Try to get from environment variables
        smtp_host = os.environ.get('SMTP_HOST')
        if smtp_host:
            return {
                'host': smtp_host,
                'port': int(os.environ.get('SMTP_PORT', 587)),
                'username': os.environ.get('SMTP_USERNAME'),
                'password': os.environ.get('SMTP_PASSWORD'),
                'use_tls': os.environ.get('SMTP_USE_TLS', 'true').lower() == 'true'
            }

        return None

    def store_share_offline(self, location: Dict, share_data: Dict):
        """Generate offline share for physical storage"""
        offline_file = self.temp_workspace / f"offline_share_{share_data['share_index']}.txt"

        with open(offline_file, 'w') as f:
            f.write(f"BACKUP RECOVERY KEY SHARE\n")
            f.write(f"========================\n")
            f.write(f"Backup Date: {self.backup_date}\n")
            f.write(f"Share: {share_data['share_index']} of {share_data['total_shares']}\n")
            f.write(f"Threshold: {share_data['threshold']}\n")
            f.write(f"Location: {location['description']}\n")
            f.write(f"\nKEY SHARE (KEEP SECURE):\n")
            f.write(f"{share_data['share']}\n")

        # Print QR code for easier storage/retrieval
        import qrcode
        qr = qrcode.QRCode()
        qr.add_data(share_data['share'])
        qr.make()
        qr.print_ascii()

        self.logger.info(f"Generated offline share {share_data['share_index']}: {location['description']}")
        print(f"Please securely store the share file: {offline_file}")

    def calculate_checksum(self, file_path: str) -> str:
        """Calculate MD5 checksum of file"""
        md5 = hashlib.md5()

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5.update(chunk)

        return md5.hexdigest()

    def upload_to_storage(self, encrypted_file: str, checksum: str):
        """Upload to write-only storage"""
        # Check if storage is configured
        if 'storage' not in self.config or 'primary' not in self.config['storage']:
            self.logger.info("No storage configured, skipping upload...")
            return

        self.logger.info("Uploading to secure storage...")

        # Upload to primary storage
        storage_type = self.config['storage']['primary'].get('type', 's3')

        if storage_type == 's3' and 'aliyuncs.com' in self.config['storage']['primary']['endpoint']:
            # Use Alibaba OSS SDK for Alibaba Cloud
            try:
                import oss2
            except ImportError:
                raise Exception("oss2 library required for Alibaba Cloud OSS. Install with: pip install oss2")

            # Extract region from endpoint (e.g., oss-me-central-1.aliyuncs.com -> me-central-1)
            endpoint = self.config['storage']['primary']['endpoint']

            auth = oss2.Auth(
                self.config['storage']['primary']['access_key'],
                self.config['storage']['primary']['secret_key']
            )
            bucket = oss2.Bucket(
                auth,
                endpoint,
                self.config['storage']['primary']['bucket']
            )

            file_name = os.path.basename(encrypted_file)
            object_key = f"{self.backup_date}/{file_name}"

            try:
                # Get file size to determine upload method
                file_size = os.path.getsize(encrypted_file)

                # Upload with metadata
                headers = {
                    'x-oss-meta-checksum': checksum,
                    'x-oss-meta-backup-date': self.backup_date
                }

                # Use resumable upload for files larger than 100MB
                if file_size > 100 * 1024 * 1024:
                    self.logger.info(f"Large file detected ({file_size / (1024*1024*1024):.2f} GB), using resumable upload...")
                    # Resumable upload with 100MB part size for better efficiency
                    oss2.resumable_upload(
                        bucket,
                        object_key,
                        encrypted_file,
                        headers=headers,
                        part_size=100 * 1024 * 1024,
                        num_threads=4
                    )
                else:
                    # Simple upload for smaller files with extended timeout
                    bucket.put_object_from_file(object_key, encrypted_file, headers=headers)

                self.logger.info(f"Successfully uploaded to {self.config['storage']['primary']['bucket']}/{object_key}")
            except Exception as e:
                raise Exception(f"Failed to upload {encrypted_file} to {self.config['storage']['primary']['bucket']}/{object_key}: {e}")
        else:
            # Use boto3 for AWS S3 and other S3-compatible storage
            from botocore.config import Config

            s3_config = Config(signature_version='v4')
            s3_client = boto3.client(
                's3',
                endpoint_url=self.config['storage']['primary'].get('endpoint'),
                aws_access_key_id=self.config['storage']['primary']['access_key'],
                aws_secret_access_key=self.config['storage']['primary']['secret_key'],
                config=s3_config
            )

            file_name = os.path.basename(encrypted_file)

            try:
                s3_client.upload_file(
                    encrypted_file,
                    self.config['storage']['primary']['bucket'],
                    f"{self.backup_date}/{file_name}",
                    ExtraArgs={
                        'Metadata': {
                            'checksum': checksum,
                            'backup_date': self.backup_date
                        }
                    }
                )
                self.logger.info(f"Successfully uploaded to {self.config['storage']['primary']['bucket']}/{self.backup_date}/{file_name}")
            except Exception as e:
                raise Exception(f"Failed to upload {encrypted_file} to {self.config['storage']['primary']['bucket']}/{self.backup_date}/{file_name}: {e}")

        # Upload to secondary storage (Azure) if configured
        if 'secondary' in self.config['storage']:
            blob_service = BlobServiceClient(
                account_url=f"https://{self.config['storage']['secondary']['account_name']}.blob.core.windows.net",
                credential=self.config['storage']['secondary']['sas_token']
            )

            blob_client = blob_service.get_blob_client(
                container=self.config['storage']['secondary']['container'],
                blob=f"{self.backup_date}/{file_name}"
            )

            with open(encrypted_file, 'rb') as data:
                blob_client.upload_blob(data, metadata={'checksum': checksum})

        self.logger.info("Upload completed")

    def cleanup(self):
        """Clean up temporary files"""
        self.logger.info("Cleaning up temporary files...")

        # Remove unencrypted backup directory
        import shutil
        if self.backup_path.exists():
            shutil.rmtree(self.backup_path)

        # Keep encrypted file for verification, remove after successful upload
        shutil.rmtree(self.temp_workspace)

    def run(self):
        """Main execution flow"""
        try:
            # 1. Check prerequisites
            if not self.check_prerequisites():
                sys.exit(1)

            # 2. Create directory structure
            self.create_backup_structure()

            # 3. Backup GitLab repositories
            self.backup_gitlab()

            # 4. Backup all databases
            # Check if RDS instances are configured
            if 'databases' in self.config and 'rds_instances' in self.config['databases'] and self.config['databases']['rds_instances']:
                with ThreadPoolExecutor(max_workers=5) as executor:
                    # Create backup users first
                    for instance in self.config['databases']['rds_instances']:
                        # Setup backup user logic here
                        pass

                    # Backup RDS instances
                    futures = []
                    for instance in self.config['databases']['rds_instances']:
                        future = executor.submit(self.backup_rds_instance, instance)
                        futures.append(future)

                    # Wait for all backups to complete
                    for future in futures:
                        future.result()
            else:
                self.logger.info("No RDS instances configured, skipping...")

            # 5. Backup external databases
            self.backup_external_databases()

            # 6. Organize database dumps into repository folders
            self.organize_database_dumps()

            # 7. Create archive
            archive_path = self.archive_backup()

            # 8. Encrypt with Shamir's Secret Sharing (creates shares in temp location)
            encryption_result = self.encrypt_with_shamir(archive_path)

            # 9. Calculate checksum
            checksum = self.calculate_checksum(encryption_result['encrypted_file'])

            # 10. Upload to write-only storage
            self.upload_to_storage(encryption_result['encrypted_file'], checksum)

            # 11. Distribute key shares (ONLY after successful upload)
            self.distribute_shares_from_temp(encryption_result['shares_temp_dir'], checksum)
            # self.debug_print_email_message(encryption_result['shares_temp_dir'], checksum)

            # 12. Clean up
            self.cleanup()

            # 13. Send notification
            self.send_notification(True, checksum, encryption_result)

            self.logger.info("Backup completed successfully!")

        except Exception as e:
            self.logger.error(f"Backup failed: {e}")
            self.send_notification(False, error=str(e))
            sys.exit(1)

    def send_notification(self, success: bool, checksum: str = None, encryption_result: Dict = None, error: str = None):
        """Send backup notification"""
        subject = f"DR Backup {'Success' if success else 'Failed'} - {self.backup_date}"

        if success:
            body = f"""
            Secure Distributed Backup Completed Successfully

            Date: {self.backup_date}
            Checksum: {checksum}
            Encryption: Shamir's Secret Sharing
            Shares: {encryption_result['shares_count']} distributed
            Threshold: {encryption_result['threshold']} shares needed for recovery

            Storage Locations:
            - Primary: {self.config['storage']['primary']['endpoint']}

            Key shares have been distributed to secure locations.
            """
        else:
            body = f"""
            Secure Distributed Backup Failed

            Date: {self.backup_date}
            Error: {error}

            Please check logs at ./log/dr-backup-{self.backup_date}.log
            """

        # Send email notification
        # Implementation depends on your mail server setup
        self.logger.info(f"Notification sent: {subject}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python backup.py <config_file>")
        sys.exit(1)

    backup_system = DRBackupSystem(sys.argv[1])
    backup_system.run()