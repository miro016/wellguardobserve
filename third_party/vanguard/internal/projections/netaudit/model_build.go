package netaudit

// BuildModel assembles the Model from the collection's capture audit and any notes
// about the audit as a whole. It computes the deterministic rollup so the report
// renders one consistent summary.
func BuildModel(capture CaptureAudit, notes []string) Model {
	s := Summary{
		CaptureStatus: capture.Health.Status,
		Packets:       capture.Health.PacketCount,
	}
	// Violations are counted per conversation (the compact table rows); rule
	// verdicts count per configured rule (the rule-assessment rows).
	for i := range capture.Violations {
		if capture.Violations[i].Verdict == VerdictViolationConfirmed {
			s.ViolationsConfirmed++
		} else {
			s.ViolationsPossible++
		}
	}
	for i := range capture.Rules {
		switch capture.Rules[i].Verdict {
		case VerdictZeroContactCorroborated:
			s.RulesCorroborated++
		case VerdictNotExercised:
			s.RulesNotExercised++
		case VerdictInconclusive:
			s.RulesInconclusive++
		default:
			// Confirmed/possible verdicts are counted per violation above.
		}
	}
	return Model{Summary: s, Capture: capture, Notes: notes}
}
