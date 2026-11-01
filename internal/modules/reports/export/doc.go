// Package export is the export path of the reports module (reports.md §7, row B9; spec reports-2a §8.3,
// FR-16 to FR-22): create an export of a stored run, the reports.export job that serialises it, the
// creator's download, early delete and the audit kinds.
//
// It serialises the run's stored result and nothing else. Rows come from run.StoredSource (report_run_rows
// by ordinal), never from the directory and never through reportsql (RP3, ADR-0010 rule 4). Bytes come only
// from the P7 encoders (export/csv, export/xlsx; FR-19): this package builds no file by hand. Every read of
// a run, at create and at download, goes through the one gate run.Service.ReadAccess (§6.6).
package export
