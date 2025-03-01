use std::ffi::{c_void, CStr, CString, OsString};
use std::{fs, io, ptr};
use std::path::Path;
use std::ptr::{copy_nonoverlapping, null_mut};
use windows::{
    core::*,
    Win32::{
        System::{
            Diagnostics::Debug::{
                sfMax,
                ReadProcessMemory,
                IMAGE_SECTION_HEADER,
                IMAGE_FILE_HEADER,
                IMAGE_OPTIONAL_HEADER64,
                IMAGE_NT_HEADERS64,
                IMAGE_DATA_DIRECTORY,
                IMAGE_DIRECTORY_ENTRY_EXPORT,
                ImageDirectoryEntryToData,
                ImageRvaToVa,
                IMAGE_NT_OPTIONAL_HDR32_MAGIC,
                IMAGE_NT_OPTIONAL_HDR64_MAGIC
            },

            SystemServices::{
                IMAGE_EXPORT_DIRECTORY,
                IMAGE_DOS_HEADER,
                IMAGE_DOS_SIGNATURE,
                IMAGE_NT_SIGNATURE
            },


        },

    }
};


pub struct module {
    /// The index of which the module is loaded in memory
    pub index: u16,

    /// The name of the module if exists
    pub name: Option<[i8; 260]>,

    /// whether the module is valid to be read
    pub valid: Option<bool>,

    /// The size (in bytes) of the module loaded in the process memory.
    pub virtual_base: u64,

    /// The size (in bytes) of the module as loaded.
    pub virtual_size: u64,

    /// The data (Vec<u8> of bytes) of the module loaded from the dirty process' memory
    pub dirty_data: Option<Vec<u8>>,

    /// The data (Vec<u8> of bytes) of the module loaded from the clean(ish) file from disk
    pub clean_data: Option<Vec<u8>>,

    /// name and file path of the file of the module on disk
    pub file_path: [i8; 260],

    ///vector to show which pages are valid or not
    pub pages_valid: Vec<bool>,


}

impl module {
    pub fn new( virtual_base: u64, virtual_size: u64, index: u16, file_path: [i8; 260]) -> Self {
        Self {
            index,
            name: None, // Wrap in Some since it's provided
            valid: None, // Wrap in Some since it's provided
            virtual_base,
            virtual_size,
            dirty_data: None,   // Optional, set to None
            clean_data: None,   // Optional, set to None
            file_path,
            pages_valid: Vec::new(),
        }
    }

    pub fn get_dirty_buffer(&self) -> Option<&Vec<u8>> {
        if self.valid == Some(true) {
            self.dirty_data.as_ref()
        } else {
            None
        }
    }


    pub fn check_IAT(&self) -> Result<()> {
        // Implement import table checking logic
        Ok(())
    }

    pub fn check_EAT(&self) -> Result<()> {
        // Implement export table checking logic
        Ok(())
    }

    pub fn check_PE(&self) -> Result<()> {
        // Implement export table checking logic
        Ok(())
    }

    pub fn check_code_section(&self) -> Result<()> {
        // Implement code section integrity checking logic
        Ok(())
    }

    // Additional methods as needed
    // pub fn bin_name(&self) -> &str {
    //     self.file_name()
    //         .and_then(|s| s.to_str())
    //         .unwrap_or("<unknown>")
    // }

    /// Returns a reference to the IMAGE_NT_HEADERS64 of the unmapped image.
    // pub fn get_st_nt_headers(&self) -> Option<&IMAGE_NT_HEADERS64> {
    //     let img = &self.unmapped_img;
    //     if img.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
    //         return None;
    //     }
    //     // Safety: We assume the file contains a valid DOS header.
    //     let dos_header = unsafe { &*(img.as_ptr() as *const IMAGE_DOS_HEADER) };
    //     if dos_header.e_magic != 0x5A4D { // 'MZ'
    //         return None;
    //     }
    //     let nt_offset = dos_header.e_lfanew as usize;
    //     if img.len() < nt_offset + std::mem::size_of::<IMAGE_NT_HEADERS64>() {
    //         return None;
    //     }
    //     let nt_headers = unsafe { &*(img.as_ptr().add(nt_offset) as *const IMAGE_NT_HEADERS64) };
    //     if nt_headers.Signature != 0x00004550 { // 'PE\0\0'
    //         return None;
    //     }
    //     Some(nt_headers)
    // }
    //
    // /// Returns a reference to the IMAGE_EXPORT_DIRECTORY from the unmapped image.
    // pub fn get_st_export(&self) -> Option<&IMAGE_EXPORT_DIRECTORY> {
    //     let nt_headers = self.get_st_nt_headers()?;
    //     // IMAGE_DIRECTORY_ENTRY_EXPORT is at index 0.
    //     let export_dir_data = nt_headers.OptionalHeader.DataDirectory[0];
    //     if export_dir_data.VirtualAddress == 0 || export_dir_data.Size == 0 {
    //         return None;
    //     }
    //     let offset = export_dir_data.VirtualAddress as usize;
    //     if self.unmapped_img.len() < offset + std::mem::size_of::<IMAGE_EXPORT_DIRECTORY>() {
    //         return None;
    //     }
    //     let export_dir = unsafe {
    //         &*(self.unmapped_img.as_ptr().add(offset) as *const IMAGE_EXPORT_DIRECTORY)
    //     };
    //     Some(export_dir)
    // }
    //
    //
    // /// Given a function name, searches the export directory for that function
    // /// and returns its RVA offset.
    // pub fn get_unmapped_export_offset_by_name(&self, func_name: &str) -> u32 {
    //     if func_name.is_empty() {
    //         return 0;
    //     }
    //     let mut size: DWORD = 0;
    //     unsafe {
    //         let export_dir = ImageDirectoryEntryToData(
    //             self.unmapped_img.as_ptr() as *mut std::ffi::c_void,
    //             false,
    //             IMAGE_DIRECTORY_ENTRY_EXPORT,
    //             &mut size,
    //         ) as *mut IMAGE_EXPORT_DIRECTORY;
    //         if export_dir.is_null() || size == 0 {
    //             return 0;
    //         }
    //         let export_ref = &*export_dir;
    //         let names: *mut u32 = self.va(export_ref.AddressOfNames);
    //         let functions: *mut u32 = self.va(export_ref.AddressOfFunctions);
    //         let ordinals: *mut WORD = self.va(export_ref.AddressOfNameOrdinals);
    //         if names.is_null() || functions.is_null() || ordinals.is_null() {
    //             return 0;
    //         }
    //         for i in 0..export_ref.NumberOfNames {
    //             let ordinal = *ordinals.add(i as usize);
    //             let name_ptr: *const i8 = self.va(*names.add(i as usize));
    //             if !name_ptr.is_null() {
    //                 // Convert the C string to Rust &str.
    //                 if let Ok(name_str) = CStr::from_ptr(name_ptr).to_str() {
    //                     if name_str == func_name {
    //                         return *functions.add(ordinal as usize);
    //                     }
    //                 }
    //             }
    //         }
    //     }
    //     0
    // }
    /// Look up an export’s offset by name.
    pub fn get_export_offset_by_name(&self, name: &str) -> Option<usize> {
        // Parse the raw_image’s export table.
        // Convert the function name to an RVA and return it.
        None
    }

    /// Look up an export’s offset by ordinal.
    pub fn get_export_offset_by_ordinal(&self, ordinal: u16) -> Option<usize> {
        // Similar to get_export_offset_by_name, but using ordinal.
        None
    }
}