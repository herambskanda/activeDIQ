// Package export is the typed model and the streaming runner shared by the output encoders
// (safe-primitives P7, §12): a Table is a header of Columns and rows of typed Cells, an Encoder
// (export/csv, export/xlsx) turns them into bytes, and Run / RunToBlob drive an Encoder from a
// RowSource row by row, so an export of any size is bounded in memory (O7, TM-TB15-T8).
//
// No API here or in the encoders takes a []string row, a pre-rendered fragment or a format string
// (O1). "Could a spreadsheet read this as a formula?" is decided in exactly one place, cellsafe.
package export
