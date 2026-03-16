enum FinalDecisionStatus { benign, verifiedThreat, suspicious }

extension FinalDecisionStatusX on FinalDecisionStatus {
  String get label {
    switch (this) {
      case FinalDecisionStatus.benign:
        return 'Benign';
      case FinalDecisionStatus.verifiedThreat:
        return 'Verified Threat';
      case FinalDecisionStatus.suspicious:
        return 'Suspicious';
    }
  }

  String get analystAction {
    switch (this) {
      case FinalDecisionStatus.benign:
        return 'Archive event and continue monitoring.';
      case FinalDecisionStatus.verifiedThreat:
        return 'Escalate to incident response and isolate the affected asset.';
      case FinalDecisionStatus.suspicious:
        return 'Send for analyst review with contextual notes and related logs.';
    }
  }
}
