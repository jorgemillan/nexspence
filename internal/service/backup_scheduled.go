package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/nexspence-oss/nexspence/internal/distlock"
	"github.com/nexspence-oss/nexspence/internal/domain"
	"github.com/nexspence-oss/nexspence/internal/logger"
	"github.com/nexspence-oss/nexspence/internal/repository"
	"github.com/nexspence-oss/nexspence/internal/storage"
)

const (
	backupSchedulerLockKey = "backup:scheduled-run"
	backupLockTTL          = 30 * time.Minute
	backupKeyPrefix        = "backups/"
	// backupSlotSkew is how far apart two replicas' clocks may be and still
	// be recognized as firing for the same cron slot (see ranThisSlot).
	backupSlotSkew = 10 * time.Second
	// backupScheduleSyncSpec is how often each replica re-checks the stored
	// schedule against the one it has registered (see syncSchedule).
	backupScheduleSyncSpec = "@every 1m"
)

// ErrBackupNoDestination is returned by RunScheduled when scheduling is
// enabled but no destination blob store is set — in practice because the
// store was deleted (backup_settings.blob_store_id is ON DELETE SET NULL),
// since the API refuses to enable scheduling without one. It is a failure,
// not a no-op: every cron tick records it, so the admin sees why backups
// stopped instead of a stale "last run" from before the store went away.
var ErrBackupNoDestination = errors.New("backup: scheduled backup is enabled but has no destination blob store (was it deleted?)")

// ValidateSchedule reports whether expr is a cron expression the scheduler
// accepts — the same parser cron.AddFunc uses — so callers can reject a bad
// schedule before persisting it instead of after.
func ValidateSchedule(expr string) error {
	_, err := cron.ParseStandard(expr)
	return err
}

// scheduledBackupState holds the pieces of BackupService only the scheduled
// path needs, kept separate from the manual Export/Restore/ImportRepo fields
// above so those keep working exactly as before for callers that never touch
// scheduling (e.g. every existing test in backup_service_test.go).
type scheduledBackupState struct {
	mu            sync.Mutex
	cronScheduler *cron.Cron
	entryID       cron.EntryID
	hasEntry      bool
	registered    string // schedule of the current entry, "" when there is none
}

// WithSettings attaches the scheduled-backup settings repo. Returns the same
// service for chaining, matching CleanupService.WithLocker's style.
func (s *BackupService) WithSettings(r repository.BackupSettingsRepo) *BackupService {
	s.Settings = r
	return s
}

// WithLocker sets the distributed locker used so a multi-replica deployment
// runs the scheduled backup once, not once per replica.
func (s *BackupService) WithLocker(l distlock.Locker) *BackupService {
	s.locker = l
	return s
}

// WithLogger sets the logger used by the scheduler and scheduled runs.
func (s *BackupService) WithLogger(l logger.Logger) *BackupService {
	s.log = l
	return s
}

// WithAudit sets the audit log a scheduled run's outcome is recorded to. Every
// other write to the audit trail goes through AuditMiddleware, which only
// sees real HTTP requests — a cron-triggered run never is one, so without
// this a failed scheduled backup would be visible only in structured logs
// and backup_settings.last_run_error, not in Security > Audit Log where an
// admin actually looks for "did last night's backup work."
func (s *BackupService) WithAudit(a repository.AuditRepo) *BackupService {
	s.audit = a
	return s
}

// RunScheduled exports a full backup and writes it to the configured
// destination blob store, then applies retention. Returns the written key
// (empty when it was a no-op) so callers can record it.
//
// No-op (nil error, empty key) when scheduling is disabled. Enabled with no
// destination store is ErrBackupNoDestination, not a no-op.
func (s *BackupService) RunScheduled(ctx context.Context) (key string, err error) {
	if s.Settings == nil {
		return "", errors.New("backup: scheduled backup is not configured (no settings repo wired)")
	}
	settings, err := s.Settings.Get(ctx)
	if err != nil {
		return "", fmt.Errorf("backup: load settings: %w", err)
	}
	if !settings.Enabled {
		return "", nil
	}
	if settings.BlobStoreID == "" {
		return "", ErrBackupNoDestination
	}

	// Unlike storeFor's per-asset fallback in Export/Restore (defensible
	// there — every store still holds real product data, so "use the
	// default" is a reasonable best-effort), a resolution failure here must
	// be a hard error: the whole point of choosing a destination store is to
	// get bytes OUT of the default one, so silently falling back to it would
	// misdirect every scheduled backup to the wrong place while still
	// reporting success — exactly the class of bug this feature exists to
	// avoid, not reintroduce for itself.
	if s.Resolver == nil {
		return "", errors.New("backup: no store resolver configured, cannot resolve the destination blob store")
	}
	bs, err := s.BlobStores.GetByID(ctx, settings.BlobStoreID)
	if err != nil || bs == nil {
		return "", fmt.Errorf("backup: destination blob store %s not found", settings.BlobStoreID)
	}
	store, err := s.Resolver.Get(ctx, storage.BlobStoreDescriptor{ID: bs.ID, Type: bs.Type, Config: bs.Config})
	if err != nil || store == nil {
		return "", fmt.Errorf("backup: resolve destination store %s (%s): %w", bs.Name, bs.ID, err)
	}

	// Put needs a known size, and the archive's final size isn't known until
	// Export finishes writing it — spool to a temp file first, the same
	// approach backup_import.go already uses for the inbound side.
	tmp, err := os.CreateTemp("", "nexspence-scheduled-backup-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("backup: create spool file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := s.Export(ctx, tmp); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("backup: export: %w", err)
	}
	size, err := tmp.Seek(0, io.SeekCurrent)
	if err == nil {
		_, err = tmp.Seek(0, io.SeekStart)
	}
	if err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("backup: seek spool file: %w", err)
	}

	key = fmt.Sprintf("%snexspence-backup-%s.tar.gz", backupKeyPrefix, time.Now().UTC().Format("20060102-150405"))
	putErr := store.Put(ctx, key, tmp, size)
	_ = tmp.Close()
	if putErr != nil {
		return "", fmt.Errorf("backup: put %s: %w", key, putErr)
	}
	// Deliberately not counted in blob_stores.used_bytes: that counter is
	// derived from asset rows (RecomputeUsedBytes rebuilds it from them
	// alone), and a backup has none, so any manual increment here would be
	// wiped by the next recompute and then under-count on every retention
	// delete. A quota on the destination store therefore covers artifacts
	// only, not backups.

	s.applyRetention(ctx, store, settings.RetentionCount)
	return key, nil
}

// applyRetention keeps the retentionCount most recently modified backups/
// entries in store, deleting older ones. No-op for retentionCount <= 0
// (unlimited) — an explicit opt-out, not the zero-value default (Get returns
// 7 when the settings row has never been written).
func (s *BackupService) applyRetention(ctx context.Context, store storage.BlobStore, retentionCount int) {
	if retentionCount <= 0 {
		return
	}
	// A store shared with unrelated product data can hold far more than this
	// feature's own handful of backups — ask for just the "backups/" prefix
	// natively when the backend supports it (S3/Azure), instead of paging
	// through the whole store on every scheduled run just to find our own
	// entries (#490 review).
	var (
		entries []storage.BlobEntry
		err     error
	)
	if pl, ok := store.(storage.PrefixListableStore); ok {
		entries, err = pl.ListEntriesWithPrefix(ctx, backupKeyPrefix)
	} else {
		entries, err = store.ListEntries(ctx)
	}
	if err != nil {
		s.logWarn("backup retention: list entries failed", "err", err)
		return
	}
	var backups []storage.BlobEntry
	for _, e := range entries {
		if strings.HasPrefix(e.Key, backupKeyPrefix) {
			backups = append(backups, e)
		}
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].ModTime.After(backups[j].ModTime) })
	if len(backups) <= retentionCount {
		return
	}
	for _, e := range backups[retentionCount:] {
		if err := store.Delete(ctx, e.Key); err != nil {
			s.logWarn("backup retention: delete failed", "key", e.Key, "err", err)
		}
	}
}

// StartScheduler starts the cron entry for the configured schedule and blocks
// until ctx is canceled. Run as a goroutine (main.go).
func (s *BackupService) StartScheduler(ctx context.Context) {
	s.sched.mu.Lock()
	s.sched.cronScheduler = cron.New(cron.WithChain(cron.Recover(cron.DefaultLogger)))
	s.sched.mu.Unlock()

	if err := s.ReloadSchedule(ctx); err != nil {
		s.logError("backup: failed to load schedule", "err", err)
	}
	// ReloadSchedule only runs on the replica that served the PUT; every other
	// replica picks the change up here instead — including one that started
	// with scheduling disabled and so has no entry to notice it with. Without
	// this, a multi-replica deployment backs up only while that one replica
	// is alive.
	if _, err := s.sched.cronScheduler.AddFunc(backupScheduleSyncSpec, func() { s.syncSchedule(context.Background()) }); err != nil {
		s.logError("backup: failed to start schedule sync", "err", err)
	}
	s.sched.cronScheduler.Start()
	<-ctx.Done()
	s.sched.cronScheduler.Stop()
}

// syncSchedule re-registers the cron entry when the stored schedule no longer
// matches the one this replica has registered ("" when it has none).
func (s *BackupService) syncSchedule(ctx context.Context) {
	if s.Settings == nil {
		return
	}
	cur, err := s.Settings.Get(ctx)
	if err != nil {
		return
	}
	want := ""
	if cur.Enabled {
		want = cur.ScheduleCron
	}
	s.sched.mu.Lock()
	have := s.sched.registered
	s.sched.mu.Unlock()
	if want == have {
		return
	}
	if err := s.ReloadSchedule(ctx); err != nil {
		s.logError("backup: failed to sync schedule", "err", err)
	}
}

// ReloadSchedule re-reads backup_settings and re-registers the cron entry, so
// a change made through PUT /api/v1/backup/settings takes effect without a
// restart — same UX as CleanupService.ReloadPolicy.
func (s *BackupService) ReloadSchedule(ctx context.Context) error {
	s.sched.mu.Lock()
	defer s.sched.mu.Unlock()
	if s.sched.cronScheduler == nil {
		return nil // scheduler not started yet — StartScheduler will call this itself
	}
	if s.sched.hasEntry {
		s.sched.cronScheduler.Remove(s.sched.entryID)
		s.sched.hasEntry = false
		s.sched.registered = ""
	}
	if s.Settings == nil {
		return nil
	}
	settings, err := s.Settings.Get(ctx)
	if err != nil {
		return err
	}
	if !settings.Enabled || settings.ScheduleCron == "" {
		return nil
	}
	registered := settings.ScheduleCron
	id, err := s.sched.cronScheduler.AddFunc(registered, func() { s.runScheduledTick(context.Background(), registered) })
	if err != nil {
		return fmt.Errorf("backup: invalid schedule_cron %q: %w", settings.ScheduleCron, err)
	}
	s.sched.entryID, s.sched.hasEntry, s.sched.registered = id, true, registered
	return nil
}

// runScheduledTick is the cron entry's body. ReloadSchedule only runs on the
// replica that served PUT /api/v1/backup/settings, so until syncSchedule
// catches up the others still hold an entry for the previous schedule (or
// for a schedule since disabled). Check the registered expression against
// the stored one first: a stale entry re-registers itself instead of
// running at the old time.
func (s *BackupService) runScheduledTick(ctx context.Context, registered string) {
	if s.Settings != nil {
		if cur, err := s.Settings.Get(ctx); err == nil && (!cur.Enabled || cur.ScheduleCron != registered) {
			if err := s.ReloadSchedule(ctx); err != nil {
				s.logError("backup: failed to reload a stale schedule", "err", err)
			}
			return
		}
	}
	s.runOnce(ctx)
}

func (s *BackupService) runOnce(ctx context.Context) {
	start := time.Now()
	if s.locker != nil {
		lock, err := s.locker.Acquire(ctx, backupSchedulerLockKey, backupLockTTL)
		if errors.Is(err, distlock.ErrLockHeld) {
			return // another replica is already running the scheduled backup
		}
		if err != nil {
			s.logWarn("backup: lock acquire failed, running unlocked", "err", err)
		} else {
			defer func() { _ = lock.Release(ctx) }()
		}
	}
	// The lock only covers a run in progress. A replica whose clock is a
	// little behind fires the same cron slot after the first one has already
	// finished and released it; a second backup would then spend a retention
	// slot for nothing, so skip a slot that already has a recorded run.
	if s.ranThisSlot(ctx, start) {
		return
	}
	key, runErr := s.RunScheduled(ctx)
	if runErr == nil && key == "" {
		// Disabled between the cron tick and this read — nothing ran, so
		// there is nothing to record.
		return
	}
	errMsg := ""
	if runErr != nil {
		errMsg = runErr.Error()
		s.logError("scheduled backup failed", "err", runErr)
	} else {
		s.logInfo("scheduled backup complete", "key", key)
	}
	if s.Settings != nil {
		// The start time, not the end: ranThisSlot compares it with the cron
		// slot the next tick belongs to, and a long export must not push it
		// into that slot.
		if err := s.Settings.RecordRun(ctx, start, key, errMsg); err != nil {
			s.logWarn("backup: record run failed", "err", err)
		}
	}
	s.recordAuditEvent(ctx, key, runErr)
}

// ranThisSlot reports whether a run was already recorded for the cron slot
// that started at or just before now. Cron slots are whole minutes, so the
// slot is now truncated to the minute, widened by backupSlotSkew for a
// replica whose clock runs slightly ahead. A settings read failure is not a
// reason to skip a backup.
func (s *BackupService) ranThisSlot(ctx context.Context, now time.Time) bool {
	if s.Settings == nil {
		return false
	}
	cur, err := s.Settings.Get(ctx)
	if err != nil || cur.LastRunAt == nil {
		return false
	}
	return !cur.LastRunAt.Before(now.Truncate(time.Minute).Add(-backupSlotSkew))
}

// recordAuditEvent writes the outcome of a scheduled run to Security > Audit
// Log. Best-effort: an audit-write failure is logged but never turns a
// successful backup into a reported failure, or vice versa.
func (s *BackupService) recordAuditEvent(ctx context.Context, key string, runErr error) {
	if s.audit == nil {
		return
	}
	result := "success"
	ctxData := map[string]any{"key": key}
	if runErr != nil {
		result = "failure"
		ctxData["error"] = runErr.Error()
	}
	event := &domain.AuditEvent{
		EventTime:  time.Now(),
		Username:   "system",
		Domain:     "SYSTEM",
		Action:     "BACKUP",
		EntityType: "backup",
		EntityName: key,
		Context:    ctxData,
		Result:     result,
	}
	if err := s.audit.Write(ctx, event); err != nil {
		s.logWarn("backup: audit write failed", "err", err)
	}
}

// log* tolerate a nil s.log (scheduling wired up without a logger), matching
// how the rest of this codebase's optional loggers behave.
func (s *BackupService) logWarn(msg string, kv ...any) {
	if s.log != nil {
		s.log.Warnw(msg, kv...)
	}
}
func (s *BackupService) logError(msg string, kv ...any) {
	if s.log != nil {
		s.log.Errorw(msg, kv...)
	}
}
func (s *BackupService) logInfo(msg string, kv ...any) {
	if s.log != nil {
		s.log.Infow(msg, kv...)
	}
}
