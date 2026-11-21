// Package replstatus serves ReadReplicationStatus (connector-contract §5.6, rules 1 to 9; spec
// reports-2-second-slice §7.3, D14): a per-DC, read-only replication status with explicit coverage.
//
// For every DC in scope the handler reads the four msDS-Repl* attributes in XML form through
// ad.Session.ReadReplication (no control, no ";binary", no binary-blob fallback), hands each value to
// the one decoder, replxml, and maps the result to ReplicationState. A fact the DC does not return
// is unset or NOT_RETURNED, never zero. A value the decoder refuses is DECODE_FAILED with the
// decoder's fixed code; the raw text is never copied into a response or a log.
//
// DC enumeration and per-DC sessions are seams (DCLister, Opener): the Describe domain-controller
// section is another group's, so this package does not discover DCs itself. BoundDC adapts the one
// session of a single-DC connection to both seams.
package replstatus
