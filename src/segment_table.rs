// the flattened segment table is optimized for lookup of segments while
// still being serializeable. All numbers are little endian
// flattened segment in the following format:
//
// struct FlattenedSegmentTable {
//      magic: "seg\0",
//      num_files: u32,
//      files: [FileReplaceHeader; num_files],
//
//      // all segments are ordered by their start so they can be binary searched
//      // in the case of asking for a start not directly on the boundary of entries
//      segments: [[SegmentReplaceHeader; segment_list_entry_count]; num_files],
//
//      // the amount of data in the last section is unknown, and all the data
//      // flows together. The SegmentReplaceEntries reference this data
//      blobs: [[u8]]
//
// }
//
// struct FileReplaceHeader {
//      // pad until size is 4 byte aligned
//      name_str_len: u32,
//      segment_list_offset: u32,
//      segment_list_entry_count: u32,
//      file_name: c_str
// }
//
// #[repr(u32)]
// enum EntryType {
//      ModSegment = 0,
//      GameSegment = 1
// }
//
// struct SegmentReplaceEntry {
//      type: EntryType
//      start: u32, // start in the phantom file
//      len: u32,
//
//      // either an offset into this file, or file specified by
//      // the file name in FileReplaceHeader depending on EntryType
//      data_off: u32
// }
//
//

mod construct;
mod deconstruct;

pub use construct::from_combined_dir;
pub use construct::from_fantome_file;
