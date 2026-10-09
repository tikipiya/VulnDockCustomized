package domain

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func RandomBytes(size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

func RandomHex(size int) (string, error) {
	data, err := RandomBytes(size)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func DecodeDataURL(data string) (string, []byte, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return "", nil, errors.New("attachment data is required")
	}
	if !strings.HasPrefix(strings.ToLower(data), "data:") {
		return "", nil, errors.New("attachment data must be a data URL")
	}

	header, payload, ok := strings.Cut(data[5:], ",")
	if !ok {
		return "", nil, errors.New("data URL is missing payload")
	}

	parts := strings.Split(header, ";")
	contentType := strings.TrimSpace(parts[0])
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	isBase64 := false
	for _, part := range parts[1:] {
		if strings.EqualFold(strings.TrimSpace(part), "base64") {
			isBase64 = true
			break
		}
	}
	if !isBase64 {
		return "", nil, errors.New("data URL payload must be base64 encoded")
	}

	content, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", nil, err
	}
	return contentType, content, nil
}

func NormalizeDraft(draft ReportDraft) Report {
	conversationLogs := normalizeConversationLogs(draft.ConversationLogs, draft.MaintainerLog)

	return Report{
		ID:               strings.TrimSpace(draft.ID),
		Title:            withDefault(strings.TrimSpace(draft.Title), "Untitled report"),
		Program:          strings.TrimSpace(draft.Program),
		Asset:            strings.TrimSpace(draft.Asset),
		CVSSVersion:      normalizeChoice(draft.CVSSVersion, "3.1", []string{"3.1", "4.0"}),
		CVSSScore:        NormalizeCVSSScore(draft.CVSSScore),
		CVSSVector:       strings.TrimSpace(draft.CVSSVector),
		Status:           normalizeChoice(draft.Status, "Draft", []string{"Draft", "Submitted", "Triaged", "Resolved", "Published", "Duplicate", "Rejected", "Paid"}),
		SubmittedAt:      strings.TrimSpace(draft.SubmittedAt),
		NextActionAt:     strings.TrimSpace(draft.NextActionAt),
		RewardStatus:     normalizeRewardStatus(draft.RewardStatus),
		RewardAmount:     strings.TrimSpace(draft.RewardAmount),
		RewardCurrency:   strings.ToUpper(strings.TrimSpace(draft.RewardCurrency)),
		RewardPaidAt:     strings.TrimSpace(draft.RewardPaidAt),
		RewardNote:       strings.TrimSpace(draft.RewardNote),
		Memo:             strings.TrimSpace(draft.Memo),
		ReportURL:        strings.TrimSpace(draft.ReportURL),
		MaintainerLog:    "",
		ConversationLogs: conversationLogs,
		Tags:             normalizeTags(draft.Tags),
		PocFiles:         NormalizePocFiles(draft.PocFiles),
	}
}

func MigrateReports(stored []StoredReport) ([]Report, bool) {
	reports := make([]Report, 0, len(stored))
	hadReportContent := false
	for _, item := range stored {
		report := item.Report
		hadReportContent = hadReportContent || HasReportContent(item)
		if strings.TrimSpace(report.CVSSVersion) == "" {
			report.CVSSVersion = "3.1"
		}
		if strings.TrimSpace(report.CVSSScore) == "" {
			report.CVSSScore = legacySeverityScore(item.Severity)
		} else {
			report.CVSSScore = NormalizeCVSSScore(report.CVSSScore)
		}
		report.CVSSVector = strings.TrimSpace(report.CVSSVector)
		report.NextActionAt = strings.TrimSpace(report.NextActionAt)
		report.RewardStatus = normalizeRewardStatus(report.RewardStatus)
		report.RewardAmount = strings.TrimSpace(report.RewardAmount)
		report.RewardCurrency = strings.ToUpper(strings.TrimSpace(report.RewardCurrency))
		report.RewardPaidAt = strings.TrimSpace(report.RewardPaidAt)
		report.RewardNote = strings.TrimSpace(report.RewardNote)
		report.Memo = strings.TrimSpace(report.Memo)
		report.ConversationLogs = normalizeConversationLogs(report.ConversationLogs, report.MaintainerLog)
		report.MaintainerLog = ""
		report.Tags = normalizeTags(report.Tags)
		report.PocFiles = NormalizePocFiles(report.PocFiles)
		reports = append(reports, report)
	}
	return reports, hadReportContent
}

func HasReportContent(report StoredReport) bool {
	values := []string{
		report.Body,
		report.Summary,
		report.Impact,
		report.Steps,
		report.Evidence,
		report.Notes,
	}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func normalizeConversationLogs(logs []ConversationEntry, legacyLog string) []ConversationEntry {
	next := []ConversationEntry{}
	for i, log := range logs {
		body := strings.TrimSpace(log.Body)
		if body == "" {
			continue
		}

		from := normalizeParticipant(log.From, "自分")
		to := normalizeParticipant(log.To, oppositeParticipant(from))
		if from == to {
			to = oppositeParticipant(from)
		}

		id := strings.TrimSpace(log.ID)
		if id == "" {
			id = newConversationEntryID(i)
		}

		next = append(next, ConversationEntry{
			ID:             id,
			From:           from,
			To:             to,
			CommunicatedAt: strings.TrimSpace(log.CommunicatedAt),
			Body:           body,
		})
	}

	legacyLog = strings.TrimSpace(legacyLog)
	if len(next) == 0 && legacyLog != "" {
		next = append(next, ConversationEntry{
			ID:   newConversationEntryID(0),
			From: "自分",
			To:   "メンテナー",
			Body: legacyLog,
		})
	}

	return next
}

func normalizeParticipant(value string, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "自分", "me", "myself", "self":
		return "自分"
	case "メンテナー", "maintainer":
		return "メンテナー"
	default:
		return fallback
	}
}

func oppositeParticipant(value string) string {
	if value == "メンテナー" {
		return "自分"
	}
	return "メンテナー"
}

func NormalizePocFiles(files []PocFile) []PocFile {
	next := []PocFile{}
	for _, file := range files {
		id := NormalizeAttachmentID(file.ID)
		name := strings.TrimSpace(file.Name)
		path := filepath.ToSlash(strings.TrimSpace(file.Path))
		data := strings.TrimSpace(file.Data)
		if name == "" || (data == "" && path == "") {
			continue
		}
		if data == "" && ValidateLegacyAttachmentPath(path) != nil {
			continue
		}
		if file.Size < 0 {
			file.Size = 0
		}
		next = append(next, PocFile{
			ID:   id,
			Name: name,
			Type: strings.TrimSpace(file.Type),
			Size: file.Size,
			Path: path,
			Data: data,
		})
	}
	return next
}

func ValidateIncomingPocFiles(files []PocFile) error {
	for _, file := range files {
		name := strings.TrimSpace(file.Name)
		id := strings.TrimSpace(file.ID)
		path := filepath.ToSlash(strings.TrimSpace(file.Path))
		data := strings.TrimSpace(file.Data)
		if name == "" && id == "" && path == "" && data == "" {
			continue
		}
		if name == "" {
			return errors.New("PoC attachment name is required")
		}
		if id != "" && NormalizeAttachmentID(id) != id {
			return fmt.Errorf("PoC attachment %q id is invalid", name)
		}
		if data == "" && path == "" {
			return fmt.Errorf("PoC attachment %q path is required", name)
		}
		if path != "" {
			if err := ValidateLegacyAttachmentPath(path); err != nil {
				return fmt.Errorf("PoC attachment %q path is invalid: %w", name, err)
			}
		}
	}
	return nil
}

func ValidatePocFileMetadata(files []PocFile) error {
	for _, file := range files {
		if strings.TrimSpace(file.Data) != "" {
			continue
		}
		name := strings.TrimSpace(file.Name)
		if name == "" {
			return errors.New("PoC attachment name is required")
		}
		path := filepath.ToSlash(strings.TrimSpace(file.Path))
		if path == "" {
			return fmt.Errorf("PoC attachment %q path is required", name)
		}
		if err := ValidateLegacyAttachmentPath(path); err != nil {
			return fmt.Errorf("PoC attachment %q path is invalid: %w", name, err)
		}
		id := strings.TrimSpace(file.ID)
		if id != "" && NormalizeAttachmentID(id) != id {
			return fmt.Errorf("PoC attachment %q id is invalid", name)
		}
	}
	return nil
}

func NormalizeCVSSScore(score string) string {
	score = strings.TrimSpace(score)
	if score == "" {
		return ""
	}

	value, err := strconv.ParseFloat(score, 64)
	if err != nil {
		return ""
	}
	if value < 0 {
		value = 0
	}
	if value > 10 {
		value = 10
	}
	return strconv.FormatFloat(value, 'f', 1, 64)
}

func legacySeverityScore(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "9.0"
	case "high":
		return "7.0"
	case "medium":
		return "4.0"
	case "low":
		return "0.1"
	case "info", "none":
		return "0.0"
	default:
		return ""
	}
}

func normalizeTags(tags []string) []string {
	seen := map[string]bool{}
	next := []string{}
	for _, tag := range tags {
		tag = strings.Trim(strings.TrimSpace(tag), "#")
		if tag == "" {
			continue
		}
		key := strings.ToLower(tag)
		if seen[key] {
			continue
		}
		seen[key] = true
		next = append(next, tag)
	}
	return next
}

func normalizeRewardStatus(value string) string {
	return normalizeChoice(value, "Unknown", []string{"Unknown", "Pending", "Paid", "None"})
}

func normalizeChoice(value string, fallback string, allowed []string) string {
	value = strings.TrimSpace(value)
	for _, candidate := range allowed {
		if strings.EqualFold(value, candidate) {
			return candidate
		}
	}
	return fallback
}

func withDefault(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func SortReports(reports []Report) {
	sort.SliceStable(reports, func(i, j int) bool {
		left := reports[i].UpdatedAt
		if left == "" {
			left = reports[i].CreatedAt
		}
		right := reports[j].UpdatedAt
		if right == "" {
			right = reports[j].CreatedAt
		}
		return left > right
	})
}

func NewReportID() string {
	suffix, err := RandomHex(16)
	if err != nil {
		return "report_" + time.Now().UTC().Format("20060102150405.000000000")
	}
	return "report_" + suffix
}

func newConversationEntryID(index int) string {
	return "conversation_" + time.Now().UTC().Format("20060102150405.000000000") + "_" + strconv.Itoa(index)
}

func NewAttachmentID() string {
	suffix, err := RandomHex(16)
	if err != nil {
		return "attachment_" + time.Now().UTC().Format("20060102150405.000000000")
	}
	return "attachment_" + suffix
}

func NormalizeAttachmentID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || id == "." || id == ".." {
		return ""
	}
	for _, value := range id {
		switch {
		case value >= 'a' && value <= 'z':
		case value >= 'A' && value <= 'Z':
		case value >= '0' && value <= '9':
		case value == '_' || value == '-' || value == '.':
		default:
			return ""
		}
	}
	return id
}

func SanitizeAttachmentName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "." || name == string(filepath.Separator) || name == "" {
		return "attachment"
	}

	var builder strings.Builder
	for _, value := range name {
		switch {
		case value < 32 || value == 127:
			builder.WriteRune('_')
		case value == '"', value == '\\', value == '/':
			builder.WriteRune('_')
		default:
			builder.WriteRune(value)
		}
	}

	name = strings.TrimSpace(builder.String())
	if name == "" || name == "." || name == ".." {
		return "attachment"
	}
	return name
}
