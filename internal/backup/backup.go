package backup

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"VulnDock/internal/domain"

	"golang.org/x/crypto/argon2"
)

const (
	Format            = "vulndock.encrypted-backup.v1"
	ManifestName      = "vulndock-backup.json"
	PayloadName       = "payload.bin"
	Algorithm         = "AES-256-GCM"
	KDF               = "argon2id"
	KDFTime           = uint32(3)
	KDFMemory         = uint32(64 * 1024)
	KDFThreads        = uint8(4)
	KDFKeyLen         = uint32(32)
	MaxEncryptedBytes = 256 * 1024 * 1024
)

var maxZipEntryBytes = MaxEncryptedBytes

// SetMaxZipEntryBytesForTest adjusts zip entry size limits in tests.
func SetMaxZipEntryBytesForTest(value int) func() {
	original := maxZipEntryBytes
	maxZipEntryBytes = value
	return func() {
		maxZipEntryBytes = original
	}
}

type KDFParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"keyLen"`
}

type Manifest struct {
	Format    string    `json:"format"`
	Algorithm string    `json:"algorithm"`
	KDF       string    `json:"kdf"`
	KDFParams KDFParams `json:"kdfParams"`
	Salt      string    `json:"salt"`
	Nonce     string    `json:"nonce"`
}

type Attachment struct {
	Path string `json:"path"`
	Data string `json:"data"`
}

type Payload struct {
	Format      string               `json:"format"`
	Reports     []domain.Report      `json:"reports"`
	Attachments []Attachment         `json:"attachments"`
	Prompts     []domain.SavedPrompt `json:"prompts,omitempty"`
}

type ImportResult struct {
	Reports     []domain.Report
	Attachments map[string][]byte
	Prompts     []domain.SavedPrompt
}

type Result struct {
	FileName string
	Data     []byte
}

func ValidatePassword(password string) error {
	if strings.TrimSpace(password) == "" {
		return errors.New("backup password is required")
	}
	return nil
}

func DecodeArchiveData(data string) ([]byte, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return nil, errors.New("backup archive is required")
	}
	if strings.HasPrefix(strings.ToLower(data), "data:") {
		_, payload, ok := strings.Cut(data, ",")
		if !ok {
			return nil, errors.New("backup archive data URL is missing payload")
		}
		data = payload
	}
	return base64.StdEncoding.DecodeString(data)
}

func ExportZip(reports []domain.Report, prompts []domain.SavedPrompt, readAttachment func(domain.PocFile) ([]byte, error), password string) (Result, error) {
	if err := ValidatePassword(password); err != nil {
		return Result{}, err
	}
	payload, err := BuildPayload(reports, prompts, readAttachment)
	if err != nil {
		return Result{}, err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return Result{}, err
	}
	manifest, ciphertext, err := EncryptPayload(payloadJSON, password)
	if err != nil {
		return Result{}, err
	}
	archive, err := BuildZip(manifest, ciphertext)
	if err != nil {
		return Result{}, err
	}
	suffix, err := RandomHex(6)
	if err != nil {
		return Result{}, err
	}
	return Result{
		FileName: "vulndock-backup-" + suffix + ".zip",
		Data:     archive,
	}, nil
}

func ImportZip(archive []byte, password string) (ImportResult, error) {
	if err := ValidatePassword(password); err != nil {
		return ImportResult{}, err
	}
	if len(archive) > MaxEncryptedBytes {
		return ImportResult{}, errors.New("backup archive is too large")
	}
	manifest, ciphertext, err := ReadZip(archive)
	if err != nil {
		return ImportResult{}, err
	}
	payloadJSON, err := DecryptPayload(manifest, ciphertext, password)
	if err != nil {
		return ImportResult{}, err
	}
	var payload Payload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return ImportResult{}, err
	}
	if payload.Format != Format {
		return ImportResult{}, errors.New("unsupported encrypted backup payload")
	}
	return NormalizePayload(payload)
}

func BuildPayload(reports []domain.Report, prompts []domain.SavedPrompt, readAttachment func(domain.PocFile) ([]byte, error)) (Payload, error) {
	domain.EnsureReportsList(reports)
	if prompts == nil {
		prompts = []domain.SavedPrompt{}
	}
	payload := Payload{
		Format:  Format,
		Reports: reports,
		Prompts: prompts,
	}
	seen := map[string]bool{}
	for _, report := range reports {
		for _, file := range report.PocFiles {
			relPath := filepath.ToSlash(strings.TrimSpace(file.Path))
			if relPath == "" || seen[relPath] {
				continue
			}
			if err := domain.ValidateLegacyAttachmentPath(relPath); err != nil {
				return Payload{}, err
			}
			content, err := readAttachment(file)
			if err != nil {
				return Payload{}, fmt.Errorf("read PoC attachment %q: %w", file.Name, err)
			}
			payload.Attachments = append(payload.Attachments, Attachment{
				Path: relPath,
				Data: base64.StdEncoding.EncodeToString(content),
			})
			seen[relPath] = true
		}
	}
	return payload, nil
}

func NormalizePayload(payload Payload) (ImportResult, error) {
	if err := validateReportAttachmentPaths(payload.Reports); err != nil {
		return ImportResult{}, err
	}
	if err := validateBackupPrompts(payload.Prompts); err != nil {
		return ImportResult{}, err
	}
	stored := make([]domain.StoredReport, 0, len(payload.Reports))
	for _, report := range payload.Reports {
		stored = append(stored, domain.StoredReport{Report: report})
	}
	reports, _ := domain.MigrateReports(stored)

	attachments := map[string][]byte{}
	for _, attachment := range payload.Attachments {
		relPath := filepath.ToSlash(strings.TrimSpace(attachment.Path))
		if err := domain.ValidateLegacyAttachmentPath(relPath); err != nil {
			return ImportResult{}, err
		}
		content, err := base64.StdEncoding.DecodeString(attachment.Data)
		if err != nil {
			return ImportResult{}, fmt.Errorf("decode backup attachment %q: %w", relPath, err)
		}
		attachments[relPath] = content
	}
	for _, report := range reports {
		for _, file := range report.PocFiles {
			relPath := filepath.ToSlash(strings.TrimSpace(file.Path))
			if relPath == "" {
				continue
			}
			if err := domain.ValidateLegacyAttachmentPath(relPath); err != nil {
				return ImportResult{}, err
			}
			if _, ok := attachments[relPath]; !ok {
				return ImportResult{}, fmt.Errorf("backup is missing attachment content for %q", relPath)
			}
		}
	}
	domain.EnsureReportsList(reports)
	prompts := payload.Prompts
	if prompts == nil {
		prompts = []domain.SavedPrompt{}
	}
	return ImportResult{Reports: reports, Attachments: attachments, Prompts: prompts}, nil
}

func validateBackupPrompts(prompts []domain.SavedPrompt) error {
	return domain.ValidateRestoredPrompts(prompts)
}

func validateReportAttachmentPaths(reports []domain.Report) error {
	for _, report := range reports {
		for _, file := range report.PocFiles {
			path := filepath.ToSlash(strings.TrimSpace(file.Path))
			if path == "" {
				continue
			}
			if err := domain.ValidateLegacyAttachmentPath(path); err != nil {
				return fmt.Errorf("backup report %q contains invalid attachment path: %w", report.Title, err)
			}
		}
	}
	return nil
}

func EncryptPayload(payload []byte, password string) (Manifest, []byte, error) {
	salt, err := randomBytes(16)
	if err != nil {
		return Manifest{}, nil, err
	}
	nonce, err := randomBytes(12)
	if err != nil {
		return Manifest{}, nil, err
	}
	params := defaultKDFParams()
	key := deriveKey(password, salt, params)
	block, err := aes.NewCipher(key)
	if err != nil {
		return Manifest{}, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Manifest{}, nil, err
	}
	manifest := Manifest{
		Format:    Format,
		Algorithm: Algorithm,
		KDF:       KDF,
		KDFParams: params,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
	}
	ciphertext := gcm.Seal(nil, nonce, payload, []byte(Format))
	return manifest, ciphertext, nil
}

func DecryptPayload(manifest Manifest, ciphertext []byte, password string) ([]byte, error) {
	if manifest.Format != Format {
		return nil, errors.New("unsupported encrypted backup format")
	}
	if manifest.Algorithm != Algorithm {
		return nil, errors.New("unsupported encrypted backup encryption algorithm")
	}
	if manifest.KDF != KDF {
		return nil, errors.New("unsupported encrypted backup key derivation")
	}
	if err := validateKDFParams(manifest.KDFParams); err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(manifest.Salt)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(manifest.Nonce)
	if err != nil {
		return nil, err
	}
	key := deriveKey(password, salt, manifest.KDFParams)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid encrypted backup nonce")
	}
	payload, err := gcm.Open(nil, nonce, ciphertext, []byte(Format))
	if err != nil {
		return nil, errors.New("backup password is invalid or archive has been tampered with")
	}
	return payload, nil
}

func BuildZip(manifest Manifest, ciphertext []byte) ([]byte, error) {
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeZipFile(archive, ManifestName, manifestJSON); err != nil {
		return nil, err
	}
	if err := writeZipFile(archive, PayloadName, ciphertext); err != nil {
		return nil, err
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func ReadZip(data []byte) (Manifest, []byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return Manifest{}, nil, err
	}
	var manifest Manifest
	var ciphertext []byte
	for _, file := range reader.File {
		switch file.Name {
		case ManifestName:
			content, err := readZipEntry(file)
			if err != nil {
				return Manifest{}, nil, err
			}
			if err := json.Unmarshal(content, &manifest); err != nil {
				return Manifest{}, nil, err
			}
		case PayloadName:
			content, err := readZipEntry(file)
			if err != nil {
				return Manifest{}, nil, err
			}
			ciphertext = content
		}
	}
	if manifest.Format == "" {
		return Manifest{}, nil, errors.New("backup manifest is missing")
	}
	if len(ciphertext) == 0 {
		return Manifest{}, nil, errors.New("backup payload is missing")
	}
	return manifest, ciphertext, nil
}

func writeZipFile(archive *zip.Writer, name string, content []byte) error {
	writer, err := archive.Create(name)
	if err != nil {
		return err
	}
	_, err = writer.Write(content)
	return err
}

func readZipEntry(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, int64(maxZipEntryBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxZipEntryBytes {
		return nil, errors.New("backup zip entry is too large")
	}
	return content, nil
}

func defaultKDFParams() KDFParams {
	return DefaultKDFParams()
}

// DefaultKDFParams returns the KDF parameters used for encrypted backups.
func DefaultKDFParams() KDFParams {
	return KDFParams{Time: KDFTime, Memory: KDFMemory, Threads: KDFThreads, KeyLen: KDFKeyLen}
}

func validateKDFParams(params KDFParams) error {
	if params != defaultKDFParams() {
		return errors.New("unsupported encrypted backup key derivation parameters")
	}
	return nil
}

func deriveKey(password string, salt []byte, params KDFParams) []byte {
	return argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, params.KeyLen)
}

func randomBytes(size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

func RandomHex(size int) (string, error) {
	data, err := randomBytes(size)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}
