package domain

// EnsureReportSlices guarantees JSON encodes [] instead of null for slice fields.
func EnsureReportSlices(r *Report) {
	if r == nil {
		return
	}
	if r.Tags == nil {
		r.Tags = []string{}
	}
	if r.ConversationLogs == nil {
		r.ConversationLogs = []ConversationEntry{}
	}
	if r.PocFiles == nil {
		r.PocFiles = []PocFile{}
	}
}

// EnsureReportsList returns a non-nil slice with normalized report fields.
func EnsureReportsList(reports []Report) []Report {
	if reports == nil {
		return []Report{}
	}
	for i := range reports {
		EnsureReportSlices(&reports[i])
	}
	return reports
}
