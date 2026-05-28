package app

import policypkg "github.com/watany-dev/gokui/internal/policy"

func summarizeFindingSeverities(findings []inspectFinding) lockFindingSummary {
	out := lockFindingSummary{}
	for _, finding := range findings {
		switch finding.Severity {
		case policypkg.SeverityCritical:
			out.Critical++
		case policypkg.SeverityHigh:
			out.High++
		case policypkg.SeverityMedium:
			out.Medium++
		case policypkg.SeverityLow:
			out.Low++
		}
	}
	return out
}

func summarizeUpdateSkills(skills []updateSkillItem) updateSummary {
	out := updateSummary{Total: len(skills)}
	for _, skill := range skills {
		switch skill.Status {
		case "UP_TO_DATE":
			out.UpToDate++
		case "CHANGED":
			out.Changed++
		case reportDecisionRejected:
			out.Rejected++
		case "SKIPPED":
			out.Skipped++
		default:
			out.Errors++
		}
	}
	return out
}

func zeroUpdateRiskScore() updateRiskScore {
	return updateRiskScore{Model: updateRiskScoreModel}
}

func computeUpdateRiskScore(previous lockFindingSummary, current lockFindingSummary, signals updateRiskSignalInputs) updateRiskScore {
	previousSeverityScore := severityWeightedScore(previous)
	currentSeverityScore := severityWeightedScore(current)
	signalScore := updateSignalScore(signals)
	currentScore := currentSeverityScore + signalScore
	return updateRiskScore{
		Model:    updateRiskScoreModel,
		Previous: previousSeverityScore,
		Current:  currentScore,
		Delta:    currentScore - previousSeverityScore,
		Signals:  signalScore,
	}
}

func severityWeightedScore(summary lockFindingSummary) int {
	return (summary.Critical * updateRiskWeightCritical) +
		(summary.High * updateRiskWeightHigh) +
		(summary.Medium * updateRiskWeightMedium) +
		(summary.Low * updateRiskWeightLow)
}

func updateSignalScore(in updateRiskSignalInputs) int {
	score := 0
	score += cappedWeightedContribution(in.NewURLs, updateRiskWeightNewURL, updateRiskCapNewURL)
	score += cappedWeightedContribution(in.NewExecutables, updateRiskWeightNewExecutable, updateRiskCapNewExecutable)
	score += cappedWeightedContribution(in.FileDelta, updateRiskWeightFileDelta, updateRiskCapFileDelta)
	score += cappedWeightedContribution(in.OverrideAdded, updateRiskWeightOverrideAdd, updateRiskCapOverrideAdd)
	score += cappedWeightedContribution(in.OverrideRemoved, updateRiskWeightOverrideDrop, updateRiskCapOverrideDrop)
	return score
}

func cappedWeightedContribution(count int, weight int, absCap int) int {
	if count <= 0 || weight == 0 {
		return 0
	}
	score := count * weight
	if absCap <= 0 {
		return score
	}
	if score > absCap {
		return absCap
	}
	if score < -absCap {
		return -absCap
	}
	return score
}
