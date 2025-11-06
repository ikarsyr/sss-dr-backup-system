# Disaster Recovery Backup System

Status: Work In Progress

Enterprise backup system implementing Shamir's Secret Sharing for enhanced security. Ensures that even if the backup machine is compromised, the attacker needs multiple key shares from different locations to decrypt the backup.

## Features

- **Shamir's Secret Sharing**: Encryption key split into multiple shares, requiring a threshold number to decrypt
- **AES-GCM Encryption**: Authenticated encryption for backup archives
- **Multiple Share Storage**: Vault, AWS Secrets Manager, Azure Key Vault, local disk, and offline storage
- **GitLab Repository Backup**: Clone all repositories from a GitLab group
- **Database Backup**: Support for PostgreSQL, MySQL, MSSQL, MongoDB, and Redis
- **Configurable**: YAML-based configuration with environment variable support

## Prerequisites

- Python 3.7+
- Required Python packages:
  ```bash
  pip install pycryptodome pyyaml boto3 azure-storage-blob azure-keyvault-secrets azure-identity pymongo redis psycopg2 pymssql mysql-connector-python
  ```
- System tools: `glab`, `tar`, `pg_dump`, `mysqldump`, `mongodump` (depending on what you're backing up)

## Configuration

Create a `config.yaml` file with your backup settings:

```yaml
general:
  backup_source_base_path: .              # Source directory to backup
  backup_target_base_path: /tmp/backup   # Where encrypted backups are stored
  log_level: INFO

encryption:
  method: shamir
  total_shares: 3      # Total number of shares to create
  threshold: 2         # Minimum shares needed to decrypt
  share_locations:
    - type: local_disk
      path: /secure/share1
      description: "Backup server 1"
    - type: local_disk
      path: /secure/share2
      description: "Backup server 2"
    - type: vault
      url: https://vault.company.com
      path: /secret/backup-shares
```

See `config.yaml` for full configuration options.

## Usage

### Creating a Backup

```bash
python3 backup.py config.yaml
```

This will:
1. Check prerequisites
2. Create backup archive from source directory
3. Encrypt the archive with AES-GCM
4. Split the encryption key using Shamir's Secret Sharing
5. Distribute shares to configured locations
6. Output the encrypted backup file

**Output locations:**
- Encrypted backup: `{backup_target_base_path}/{date}/dr-backup-{date}.tar.gz.enc`
- Key shares: As configured in `share_locations`
- Logs: `./log/dr-backup-{date}.log`

### Restoring a Backup

See [RECOVER.md](RECOVER.md) for detailed recovery instructions.

**Quick recovery:**

1. Collect threshold number of share files from shareholders
2. Run the recovery script:
   ```bash
   python3 recover.py \
     --encrypted-file /path/to/backup.tar.gz.enc \
     --share /path/to/share1.json \
     --share /path/to/share2.json \
     --output restored-backup.tar.gz
   ```
3. Extract the backup:
   ```bash
   tar -xzf restored-backup.tar.gz
   ```

## Security Model

### Shamir's Secret Sharing

The backup uses Shamir's Secret Sharing to split the AES encryption key into multiple shares:

- **Total Shares**: Total number of shares created (e.g., 3)
- **Threshold**: Minimum shares needed to reconstruct the key (e.g., 2)
- **Property**: Any `threshold` number of shares can reconstruct the key, but fewer shares reveal no information

### Share Distribution

Shares are distributed to multiple locations to prevent single point of compromise:

- **Vault**: HashiCorp Vault for automated systems
- **AWS Secrets Manager**: Cloud-based secret storage
- **Azure Key Vault**: Azure cloud secret storage
- **Local Disk**: Encrypted disks or secure file systems
- **Offline**: Physical storage (printed QR codes, USB drives in safes)

### Threat Model

**Protected against:**
- Compromise of backup server (encrypted backup + distributed shares)
- Compromise of single share location (need threshold shares)
- Unauthorized access to backup storage (AES-GCM encryption)

**Requires for recovery:**
- Encrypted backup file
- Threshold number of shares from different locations
- Authorized shareholders on a call/meeting

## Architecture

```
┌─────────────────┐
│  Source Data    │
│  - GitLab Repos │
│  - Databases    │
│  - Files        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   tar + gzip    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  AES-GCM Encrypt│
│  (AES-128)      │
└────────┬────────┘
         │
         ├──────────────────┐
         │                  │
         ▼                  ▼
┌─────────────────┐  ┌─────────────────┐
│ Encrypted File  │  │  Encryption Key │
│    (.enc)       │  │   (16 bytes)    │
└─────────────────┘  └────────┬────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │ Shamir's Secret │
                     │    Sharing      │
                     └────────┬────────┘
                              │
                ┌─────────────┼─────────────┐
                ▼             ▼             ▼
           ┌────────┐    ┌────────┐    ┌────────┐
           │Share 1 │    │Share 2 │    │Share 3 │
           │ Vault  │    │  AWS   │    │ Local  │
           └────────┘    └────────┘    └────────┘
```

## File Structure

```
.
├── backup.py          # Main backup script
├── recover.py         # Recovery script
├── config.yaml        # Configuration file
├── README.md          # This file
├── RECOVER.md         # Recovery instructions
└── log/              # Log files
    └── dr-backup-{date}.log
```

## Environment Variables

Sensitive configuration values can be stored in environment variables:

```bash
export GITLAB_TOKEN="your-gitlab-token"
export DB_BACKUP_PASSWORD="database-password"
export MINIO_ACCESS_KEY="s3-access-key"
export MINIO_SECRET_KEY="s3-secret-key"
```

Reference them in `config.yaml` with `_env` suffix:
```yaml
gitlab:
  token_env: GITLAB_TOKEN  # Will read from environment variable
```

## Logging

Logs are written to both console and file:
- Location: `./log/dr-backup-{date}.log`
- Level: Configurable via `config.yaml` (DEBUG, INFO, WARNING, ERROR)

## Troubleshooting

**Issue**: "RuntimeError: dictionary changed size during iteration"
- **Fix**: Already fixed in the latest version. Update your `backup.py`.

**Issue**: "The encoded value must be an integer or a 16 byte string"
- **Fix**: Already fixed. The script uses AES-128 (16 bytes) compatible with Shamir's Secret Sharing.

**Issue**: Missing required tools
- **Fix**: Install required system tools: `glab`, `tar`, database dump utilities

**Issue**: Cannot find shares during recovery
- **Fix**: Check share locations in config. Shares are stored with naming: `share_{date}_{index}.json`

## License

Enterprise use only. See your organization's licensing terms.

## Support

For issues or questions, contact your DR team or check the logs at `./log/dr-backup-{date}.log`.
