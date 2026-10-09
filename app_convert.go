package main

import (
	"encoding/json"

	"VulnDock/internal/domain"
)

func reportsToDomain(reports []Report) []domain.Report {
	out := make([]domain.Report, 0, len(reports))
	for _, report := range reports {
		out = append(out, reportToDomain(report))
	}
	return out
}

func reportsFromDomain(reports []domain.Report) []Report {
	out := make([]Report, 0, len(reports))
	for _, report := range reports {
		out = append(out, reportFromDomain(report))
	}
	return out
}

func reportToDomain(report Report) domain.Report {
	var out domain.Report
	data, err := json.Marshal(report)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(data, &out)
	return out
}

func reportFromDomain(report domain.Report) Report {
	var out Report
	data, err := json.Marshal(report)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(data, &out)
	return out
}

func fromDomainPocFile(file domain.PocFile) PocFile {
	var out PocFile
	data, _ := json.Marshal(file)
	_ = json.Unmarshal(data, &out)
	return out
}
