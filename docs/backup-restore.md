# Backup & Restore

Nexspence supports two ways to back up an instance's data (repositories, users, roles, cleanup policies, components, assets, and blob bytes): a manual on-demand export, and a scheduled export written automatically to a chosen blob store.

## Manual (System Backup & Restore)

Admin → Backup & Restore → **Export Backup** downloads a `.tar.gz` snapshot immediately; **Restore** uploads one back. Restore is non-destructive — every record is matched against what already exists by its logical key (username, repo/blob-store name, repo+path, role/policy ID) and skipped if found, never overwritten or deleted.

A separate **Repository Import** card does the same thing scoped to a single repository (`GET /api/v1/repositories/:name/export`, `POST /api/v1/repositories/import`), with a `conflictMode` (`skip`/`merge`/`rename`) for when the target repo already exists.

Both read/write each asset's actual blob store (S3, Azure, local — whichever the asset is really on), not always the instance default.

## Scheduled Backup

Admin → Backup & Restore → **Scheduled Backup** runs a full export on a cron schedule and writes it to a blob store you choose — typically a dedicated store, created the same way as any other (Admin → Blob Stores) but left unassigned to any repository, so backups don't share storage with the artifacts they're backing up.

```yaml
# Not config.yaml — this is stored in the database (backup_settings, a
# singleton row) and edited from the UI, so a change takes effect immediately,
# no restart needed. Shown here only to describe the fields.
enabled: true
scheduleCron: "0 3 * * *"   # daily at 03:00 UTC
blobStoreId: "<uuid of a blob store created via Admin → Blob Stores>"
retentionCount: 7            # keep the 7 most recent scheduled backups; 0 = unlimited
```

Each run writes `backups/nexspence-backup-<timestamp>.tar.gz` to the configured store, then deletes the oldest entries under that prefix beyond `retentionCount`. `GET /api/v1/backup/settings` reports `lastRunAt`/`lastRunKey`/`lastRunError` so the UI can show the outcome of the previous run.

In a multi-replica deployment, only one replica runs the scheduled backup per tick — the same distributed lock (`distlock`) that already serializes cleanup, GC, and replication runs across replicas.

### Restoring a scheduled backup

Scheduled backups are plain full-instance archives — download the object from wherever it landed (the destination blob store's own console/CLI: S3, Azure, or the local filesystem path) and upload it through the same **Restore** button used for a manual export. There is no one-click "restore from the last scheduled run" — restoring is always an explicit, manual action.
