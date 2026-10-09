package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"VulnDock/internal/domain"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

type Store struct {
	db   *sql.DB
	path string
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dataDir, 0o700); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "vulndock-customized.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: dbPath}
	if _, err := s.db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(dbPath, 0o600); err != nil && !os.IsNotExist(err) {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) DBPath() string { return s.path }

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) ClearAllReports(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM reports`)
	return err
}

func (s *Store) ReportCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reports`).Scan(&n)
	return n, err
}

func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, value)
	return err
}

func (s *Store) ListReports(ctx context.Context, includeDeleted bool) ([]domain.Report, error) {
	query := `SELECT id, title, program, asset, cvss_version, cvss_score, cvss_vector, status,
		submitted_at, next_action_at, reward_status, reward_amount, reward_currency, reward_paid_at,
		reward_note, memo, report_url, tags_json, created_at, updated_at, deleted_at
		FROM reports`
	if !includeDeleted {
		query += ` WHERE deleted_at = ''`
	}
	query += ` ORDER BY updated_at DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []domain.Report
	for rows.Next() {
		var r domain.Report
		var tagsJSON string
		if err := rows.Scan(
			&r.ID, &r.Title, &r.Program, &r.Asset, &r.CVSSVersion, &r.CVSSScore, &r.CVSSVector, &r.Status,
			&r.SubmittedAt, &r.NextActionAt, &r.RewardStatus, &r.RewardAmount, &r.RewardCurrency, &r.RewardPaidAt,
			&r.RewardNote, &r.Memo, &r.ReportURL, &tagsJSON, &r.CreatedAt, &r.UpdatedAt, &r.DeletedAt,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(tagsJSON), &r.Tags); err != nil {
			return nil, err
		}
		logs, err := s.listConversationLogs(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		r.ConversationLogs = logs
		pocs, err := s.listPocFiles(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		r.PocFiles = pocs
		domain.EnsureReportSlices(&r)
		reports = append(reports, r)
	}
	return domain.EnsureReportsList(reports), rows.Err()
}

func (s *Store) listConversationLogs(ctx context.Context, reportID string) ([]domain.ConversationEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, from_participant, to_participant, communicated_at, body
		FROM conversation_logs WHERE report_id = ? ORDER BY sort_order
	`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []domain.ConversationEntry
	for rows.Next() {
		var e domain.ConversationEntry
		if err := rows.Scan(&e.ID, &e.From, &e.To, &e.CommunicatedAt, &e.Body); err != nil {
			return nil, err
		}
		logs = append(logs, e)
	}
	return logs, rows.Err()
}

func (s *Store) listPocFiles(ctx context.Context, reportID string) ([]domain.PocFile, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, content_type, size, legacy_path FROM poc_files WHERE report_id = ?
	`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var files []domain.PocFile
	for rows.Next() {
		var f domain.PocFile
		if err := rows.Scan(&f.ID, &f.Name, &f.Type, &f.Size, &f.Path); err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

func (s *Store) SaveReport(ctx context.Context, report domain.Report) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.saveReportInTx(ctx, tx, report); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) saveReportInTx(ctx context.Context, tx *sql.Tx, report domain.Report) error {
	tagsJSON, err := json.Marshal(report.Tags)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO reports(
			id, title, program, asset, cvss_version, cvss_score, cvss_vector, status,
			submitted_at, next_action_at, reward_status, reward_amount, reward_currency, reward_paid_at,
			reward_note, memo, report_url, tags_json, created_at, updated_at, deleted_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			title=excluded.title, program=excluded.program, asset=excluded.asset,
			cvss_version=excluded.cvss_version, cvss_score=excluded.cvss_score, cvss_vector=excluded.cvss_vector,
			status=excluded.status, submitted_at=excluded.submitted_at, next_action_at=excluded.next_action_at,
			reward_status=excluded.reward_status, reward_amount=excluded.reward_amount, reward_currency=excluded.reward_currency,
			reward_paid_at=excluded.reward_paid_at, reward_note=excluded.reward_note, memo=excluded.memo,
			report_url=excluded.report_url, tags_json=excluded.tags_json, updated_at=excluded.updated_at, deleted_at=excluded.deleted_at
	`, report.ID, report.Title, report.Program, report.Asset, report.CVSSVersion, report.CVSSScore, report.CVSSVector,
		report.Status, report.SubmittedAt, report.NextActionAt, report.RewardStatus, report.RewardAmount, report.RewardCurrency,
		report.RewardPaidAt, report.RewardNote, report.Memo, report.ReportURL, string(tagsJSON),
		report.CreatedAt, report.UpdatedAt, report.DeletedAt)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM conversation_logs WHERE report_id = ?`, report.ID); err != nil {
		return err
	}
	for i, log := range report.ConversationLogs {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO conversation_logs(id, report_id, sort_order, from_participant, to_participant, communicated_at, body)
			VALUES (?,?,?,?,?,?,?)
		`, log.ID, report.ID, i, log.From, log.To, log.CommunicatedAt, log.Body); err != nil {
			return err
		}
	}

	return s.syncPocFiles(ctx, tx, report)
}

func (s *Store) syncPocFiles(ctx context.Context, tx *sql.Tx, report domain.Report) error {
	keep := map[string]bool{}
	for _, file := range report.PocFiles {
		if strings.TrimSpace(file.ID) != "" {
			keep[file.ID] = true
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM poc_files WHERE report_id = ?`, report.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if !keep[id] {
			if _, err := tx.ExecContext(ctx, `DELETE FROM poc_files WHERE id = ?`, id); err != nil {
				return err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, file := range report.PocFiles {
		if strings.TrimSpace(file.Data) != "" || file.ID == "" {
			continue
		}
		_, err := tx.ExecContext(ctx, `
			UPDATE poc_files SET name = ?, content_type = ?, size = ?, legacy_path = ?
			WHERE id = ? AND report_id = ?
		`, file.Name, file.Type, file.Size, file.Path, file.ID, report.ID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UpsertPocBlob(ctx context.Context, reportID string, file domain.PocFile, content []byte) error {
	return s.upsertPocBlob(ctx, s.db, reportID, file, content)
}

func (s *Store) upsertPocBlob(ctx context.Context, exec interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
}, reportID string, file domain.PocFile, content []byte) error {
	if len(content) > domain.MaxPocFileBytes {
		return fmt.Errorf("attachment exceeds %d byte limit", domain.MaxPocFileBytes)
	}
	id := file.ID
	if id == "" {
		id = domain.NewAttachmentID()
	}
	legacyPath := file.Path
	if legacyPath == "" {
		legacyPath = domain.LegacyDisplayPath(id, file.Name)
	}
	_, err := exec.ExecContext(ctx, `
		INSERT INTO poc_files(id, report_id, name, content_type, size, content, legacy_path)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, content_type=excluded.content_type, size=excluded.size,
			content=excluded.content, legacy_path=excluded.legacy_path
	`, id, reportID, file.Name, file.Type, int64(len(content)), content, legacyPath)
	return err
}

func (s *Store) PocContent(ctx context.Context, reportID, fileID string) ([]byte, string, string, error) {
	var name, ctype string
	var content []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT pf.name, pf.content_type, pf.content
		FROM poc_files pf
		INNER JOIN reports r ON r.id = pf.report_id
		WHERE pf.id = ? AND pf.report_id = ? AND r.deleted_at = ''
	`, fileID, reportID).Scan(&name, &ctype, &content)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", "", errors.New("attachment not found")
	}
	return content, name, ctype, err
}

func (s *Store) RestoreReport(ctx context.Context, id string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.ExecContext(ctx, `
		UPDATE reports SET deleted_at = '', updated_at = ? WHERE id = ? AND deleted_at != ''
	`, now, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("report not found in trash")
	}
	return nil
}

func (s *Store) SoftDeleteReport(ctx context.Context, id string, deletedAt string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE reports SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at = ''`, deletedAt, deletedAt, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("report not found")
	}
	return nil
}

func (s *Store) PurgeDeletedBefore(ctx context.Context, cutoff time.Time) error {
	cutoffStr := cutoff.UTC().Format(time.RFC3339)
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM reports WHERE deleted_at != '' AND deleted_at < ?`, cutoffStr)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM reports WHERE id = ?`, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) InsertReportImport(ctx context.Context, report domain.Report, blobs map[string][]byte) error {
	if err := s.SaveReport(ctx, report); err != nil {
		return err
	}
	for _, file := range report.PocFiles {
		content := blobs[file.ID]
		if content == nil && file.Path != "" {
			content = blobs[file.Path]
		}
		if content == nil {
			continue
		}
		if err := s.UpsertPocBlob(ctx, report.ID, file, content); err != nil {
			return err
		}
	}
	return nil
}
