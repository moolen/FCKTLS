package fcktls

import (
	"sync"
	"time"
)

type SessionStore struct {
	mu       sync.Mutex
	sessions map[SessionKey]*sessionRecord
}

type sessionRecord struct {
	metadata SessionMetadata
	streams  PlaintextStreams
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[SessionKey]*sessionRecord),
	}
}

func (s *SessionStore) MergeMetadata(update SessionMetadataUpdate) SessionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.ensureRecord(update.Key)
	record.mergeMetadata(update)

	return record.snapshot(time.Time{})
}

func (s *SessionStore) AppendChunk(chunk PlaintextChunk) SessionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.ensureRecord(chunk.Key)
	record.touch(chunk.ObservedAt)

	switch chunk.Direction {
	case StreamDirectionClientToServer:
		record.streams.ClientToServer = append(record.streams.ClientToServer, chunk.Data...)
	case StreamDirectionServerToClient:
		record.streams.ServerToClient = append(record.streams.ServerToClient, chunk.Data...)
	}

	return record.snapshot(time.Time{})
}

func (s *SessionStore) Finalize(key SessionKey, finalizedAt time.Time) (SessionSnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.sessions[key]
	if !ok {
		return SessionSnapshot{}, false
	}

	record.touch(finalizedAt)
	snapshot := record.snapshot(finalizedAt)
	delete(s.sessions, key)

	return snapshot, true
}

func (s *SessionStore) FinalizeByPID(pid int, finalizedAt time.Time) []SessionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	var snapshots []SessionSnapshot
	for key, record := range s.sessions {
		if key.PID != pid {
			continue
		}
		record.touch(finalizedAt)
		snapshots = append(snapshots, record.snapshot(finalizedAt))
		delete(s.sessions, key)
	}
	return snapshots
}

func (s *SessionStore) ensureRecord(key SessionKey) *sessionRecord {
	record, ok := s.sessions[key]
	if ok {
		return record
	}

	record = &sessionRecord{
		metadata: SessionMetadata{
			SessionID:   key.String(),
			Key:         key,
			PID:         key.PID,
			KeyStatus:   KeyStatusUnknown,
			CaptureMode: CaptureModeMetadataOnly,
		},
	}
	s.sessions[key] = record

	return record
}

func (r *sessionRecord) mergeMetadata(update SessionMetadataUpdate) {
	r.touch(update.ObservedAt)

	if update.PID != 0 {
		r.metadata.PID = update.PID
	}
	if update.ExePath != "" {
		r.metadata.ExePath = update.ExePath
	}
	if update.LibraryPath != "" {
		r.metadata.LibraryPath = update.LibraryPath
	}
	if update.Source != nil {
		r.metadata.Source = *update.Source
	}
	if update.Destination != nil {
		r.metadata.Destination = *update.Destination
	}
	if update.Role != "" {
		r.metadata.Role = update.Role
	}
	if update.SocketFD != nil {
		r.metadata.SocketFD = cloneInt(update.SocketFD)
	}
	if update.SNI != "" {
		r.metadata.SNI = update.SNI
	}
	if update.Priority != "" {
		r.metadata.Priority = update.Priority
	}
	if update.Groups != "" {
		r.metadata.Groups = update.Groups
	}
	if update.VerifyMode != nil {
		r.metadata.VerifyMode = cloneInt(update.VerifyMode)
	}
	if update.SessionReused != nil {
		r.metadata.SessionReused = cloneBool(update.SessionReused)
	}
	if update.VerifyResult != nil {
		r.metadata.VerifyResult = cloneInt(update.VerifyResult)
	}
	if update.NegotiatedGroup != nil {
		r.metadata.NegotiatedGroup = cloneInt(update.NegotiatedGroup)
	}
	if update.TLSVersion != "" {
		r.metadata.TLSVersion = update.TLSVersion
	}
	if update.CipherSuite != "" {
		r.metadata.CipherSuite = update.CipherSuite
	}
	if update.ALPN != "" {
		r.metadata.ALPN = update.ALPN
	}
	if update.KeyStatus != "" && !shouldPreserveAvailableKeyStatus(r.metadata, update) {
		r.metadata.KeyStatus = update.KeyStatus
	}
	if update.KeyStatusNote != "" && !shouldPreserveAvailableKeyStatus(r.metadata, update) {
		r.metadata.KeyStatusNote = update.KeyStatusNote
	}
	if update.CaptureMode != "" {
		r.metadata.CaptureMode = update.CaptureMode
	}

	r.metadata.Certificates = appendUniqueCertificates(r.metadata.Certificates, update.Certificates)
	r.metadata.KeyLogLines = appendUniqueStrings(r.metadata.KeyLogLines, update.KeyLogLines)
}

func (r *sessionRecord) touch(observedAt time.Time) {
	if observedAt.IsZero() {
		return
	}
	if r.metadata.FirstSeen.IsZero() || observedAt.Before(r.metadata.FirstSeen) {
		r.metadata.FirstSeen = observedAt
	}
	if r.metadata.LastSeen.IsZero() || observedAt.After(r.metadata.LastSeen) {
		r.metadata.LastSeen = observedAt
	}
}

func (r *sessionRecord) snapshot(finalizedAt time.Time) SessionSnapshot {
	return SessionSnapshot{
		Metadata: SessionMetadata{
			SessionID:       r.metadata.SessionID,
			Key:             r.metadata.Key,
			PID:             r.metadata.PID,
			ExePath:         r.metadata.ExePath,
			LibraryPath:     r.metadata.LibraryPath,
			Source:          r.metadata.Source,
			Destination:     r.metadata.Destination,
			Role:            r.metadata.Role,
			SocketFD:        cloneInt(r.metadata.SocketFD),
			SNI:             r.metadata.SNI,
			Priority:        r.metadata.Priority,
			Groups:          r.metadata.Groups,
			VerifyMode:      cloneInt(r.metadata.VerifyMode),
			SessionReused:   cloneBool(r.metadata.SessionReused),
			VerifyResult:    cloneInt(r.metadata.VerifyResult),
			NegotiatedGroup: cloneInt(r.metadata.NegotiatedGroup),
			TLSVersion:      r.metadata.TLSVersion,
			CipherSuite:     r.metadata.CipherSuite,
			ALPN:            r.metadata.ALPN,
			Certificates:    append([]CertificateSummary(nil), r.metadata.Certificates...),
			KeyStatus:       r.metadata.KeyStatus,
			KeyStatusNote:   r.metadata.KeyStatusNote,
			KeyLogLines:     append([]string(nil), r.metadata.KeyLogLines...),
			CaptureMode:     r.metadata.CaptureMode,
			FirstSeen:       r.metadata.FirstSeen,
			LastSeen:        r.metadata.LastSeen,
		},
		Streams: PlaintextStreams{
			ClientToServer: append([]byte(nil), r.streams.ClientToServer...),
			ServerToClient: append([]byte(nil), r.streams.ServerToClient...),
		},
		FinalizedAt: finalizedAt,
	}
}

func appendUniqueStrings(existing []string, values []string) []string {
	seen := make(map[string]struct{}, len(existing))
	for _, value := range existing {
		seen[value] = struct{}{}
	}

	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		existing = append(existing, value)
		seen[value] = struct{}{}
	}

	return existing
}

func appendUniqueCertificates(existing []CertificateSummary, values []CertificateSummary) []CertificateSummary {
	seen := make(map[CertificateSummary]struct{}, len(existing))
	for _, value := range existing {
		seen[value] = struct{}{}
	}

	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		existing = append(existing, value)
		seen[value] = struct{}{}
	}

	return existing
}

func shouldPreserveAvailableKeyStatus(current SessionMetadata, update SessionMetadataUpdate) bool {
	return current.KeyStatus == KeyStatusAvailable && len(current.KeyLogLines) > 0 &&
		update.KeyStatus != "" && update.KeyStatus != KeyStatusAvailable && len(update.KeyLogLines) == 0
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	out := *value
	return &out
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	out := *value
	return &out
}
