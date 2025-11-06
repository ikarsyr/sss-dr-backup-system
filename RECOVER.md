# Backup Recovery Instructions

## Prerequisites
- Minimum 2 shareholders must be present (threshold = 2)
- Each shareholder must have their share JSON file
- Access to the encrypted backup file (.enc)

## Recovery Steps

### 1. Collect Share Files
Each shareholder should place their share file in a recovery directory:

```bash
mkdir -p /tmp/recovery/shares
```

**Shareholder 1:** Copy your share file to `/tmp/recovery/shares/share1.json`
**Shareholder 2:** Copy your share file to `/tmp/recovery/shares/share2.json`

### 2. Run Recovery Script
```bash
python3 recover.py \
  --encrypted-file /tmp/backup-workspace/2025-11-06/dr-backup-2025-11-06.tar.gz.enc \
  --share /tmp/recovery/shares/share1.json \
  --share /tmp/recovery/shares/share2.json \
  --output /tmp/recovery/restored-backup.tar.gz
```

### 3. Extract the Backup
```bash
cd /tmp/recovery
tar -xzf restored-backup.tar.gz
```

The backup contents will be extracted to the current directory.

## Quick Recovery (One-liner)

If you have the share files ready:
```bash
python3 recover.py \
  --encrypted-file dr-backup-2025-11-06.tar.gz.enc \
  --share share1.json \
  --share share2.json \
  --output restored.tar.gz && tar -xzf restored.tar.gz
```
