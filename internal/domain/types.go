package domain

type Report struct {
	ID               string              `json:"id"`
	Title            string              `json:"title"`
	Program          string              `json:"program"`
	Asset            string              `json:"asset"`
	CVSSVersion      string              `json:"cvssVersion"`
	CVSSScore        string              `json:"cvssScore"`
	CVSSVector       string              `json:"cvssVector"`
	Status           string              `json:"status"`
	SubmittedAt      string              `json:"submittedAt"`
	NextActionAt     string              `json:"nextActionAt"`
	RewardStatus     string              `json:"rewardStatus"`
	RewardAmount     string              `json:"rewardAmount"`
	RewardCurrency   string              `json:"rewardCurrency"`
	RewardPaidAt     string              `json:"rewardPaidAt"`
	RewardNote       string              `json:"rewardNote"`
	Memo             string              `json:"memo"`
	ReportURL        string              `json:"reportUrl"`
	MaintainerLog    string              `json:"maintainerLog"`
	ConversationLogs []ConversationEntry `json:"conversationLogs"`
	Tags             []string            `json:"tags"`
	PocFiles         []PocFile           `json:"pocFiles"`
	CreatedAt        string              `json:"createdAt"`
	UpdatedAt        string              `json:"updatedAt"`
	DeletedAt        string              `json:"deletedAt,omitempty"`
}

type ReportDraft struct {
	ID               string              `json:"id"`
	Title            string              `json:"title"`
	Program          string              `json:"program"`
	Asset            string              `json:"asset"`
	CVSSVersion      string              `json:"cvssVersion"`
	CVSSScore        string              `json:"cvssScore"`
	CVSSVector       string              `json:"cvssVector"`
	Status           string              `json:"status"`
	SubmittedAt      string              `json:"submittedAt"`
	NextActionAt     string              `json:"nextActionAt"`
	RewardStatus     string              `json:"rewardStatus"`
	RewardAmount     string              `json:"rewardAmount"`
	RewardCurrency   string              `json:"rewardCurrency"`
	RewardPaidAt     string              `json:"rewardPaidAt"`
	RewardNote       string              `json:"rewardNote"`
	Memo             string              `json:"memo"`
	ReportURL        string              `json:"reportUrl"`
	MaintainerLog    string              `json:"maintainerLog"`
	ConversationLogs []ConversationEntry `json:"conversationLogs"`
	Tags             []string            `json:"tags"`
	PocFiles         []PocFile           `json:"pocFiles"`
}

type ConversationEntry struct {
	ID             string `json:"id"`
	From           string `json:"from"`
	To             string `json:"to"`
	CommunicatedAt string `json:"communicatedAt"`
	Body           string `json:"body"`
}

type PocFile struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
	Path string `json:"path,omitempty"`
	Data string `json:"data,omitempty"`
}

type EncryptedBackup struct {
	FileName string `json:"fileName"`
	Data     string `json:"data"`
}

type StoredReport struct {
	Report
	Severity string `json:"severity"`
	Body     string `json:"body"`
	Summary  string `json:"summary"`
	Impact   string `json:"impact"`
	Steps    string `json:"steps"`
	Evidence string `json:"evidence"`
	Notes    string `json:"notes"`
}

const MaxPocFileBytes = 50 * 1024 * 1024

const SoftDeleteRetentionDays = 5
