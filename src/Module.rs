use crate::Function;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::{ErrorKind, Read};
use pelite::pe;
use pelite::pe::{Pe, PeFile, PeView, imports::Import};
use pelite::pe::imports::Imports;
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
use windows::Win32::Foundation::{CloseHandle, GetLastError};

pub struct module {
    /// The index of which the module is loaded in memory
    pub index: u16,

    /// The name of the module if exists
    pub name: Option<String>,

    /// whether the module is valid to be read
    pub valid: Option<bool>,

    /// The address of the module loaded in the process memory.
    pub module_base: u64,

    /// The size (in bytes) of the module as loaded.
    pub module_size: u64,

    /// The data (Vec<u8> of bytes) of the module loaded from the dirty process' memory
    pub dirty_data: Option<Vec<u8>>,

    /// The data (Vec<u8> of bytes) of the module loaded from the clean(ish) file from disk
    pub clean_data: Option<Vec<u8>>,

    /// name and file path of the file of the module on disk
    pub file_path: [i8; 260],

    ///vector to show which pages are valid or not
    pub pages_valid: Vec<bool>,

    ///vector of functions
    pub functions: Vec<Function::function>,

    ///dictionary of iat offsets 
    pub iat_dict: HashMap<String, (u64, String)>,

}

impl module {
    pub fn new(module_base: u64, module_size: u64, index: u16, file_path: [i8; 260]) -> Self {
        Self {
            index,
            name: None, // Wrap in Some since it's provided
            valid: None, // Wrap in Some since it's provided
            module_base,
            module_size,
            dirty_data: None,   // Optional, set to None
            clean_data: None,   // Optional, set to None
            file_path,
            pages_valid: Vec::new(),
            functions: Vec::new(),
            iat_dict: HashMap::new(),
        }
    }

    pub fn get_dirty_buffer(&self) -> Option<&Vec<u8>> {
        if self.valid == Some(true) {
            self.dirty_data.as_ref()
        } else {
            None
        }
    }

    pub fn read_header(&mut self) -> Result<()> {

        // Check if dirty_data exists
        let dirty_data = match self.dirty_data.as_ref() {
            Some(data) => data,
            None => {
                let err = unsafe { GetLastError() };
                println!("Error: dirty_data is None");
                return Err(Error::from(err));
            }
        };


        // Create a PeView from the byte slice
        let pe = match PeView::from_bytes(dirty_data) {
            Ok(pe) => pe,
            Err(e) => {
                let err = unsafe { GetLastError() };
                println!("Error creating PeView: {:?}", e);
                self.valid = Some(false);
                return Err(Error::from(err));
            }
        };


        // Get the import directory
        let imports = match pe.imports() {
            Ok(imports) => imports,
            Err(e) => {
                let err = unsafe { GetLastError() };
                println!("Error getting imports: {:?}", e);
                self.valid = Some(false);
                return Err(Error::from(err));
            }
        };

        // Iterate through the import descriptors
        for desc in imports {
            //get dll name for current section of the IAT
            let dll_name = match desc.dll_name() {
                Ok(name) => name,
                Err(e) => {
                    println!("Error getting DLL name: {:?}", e);
                    continue; // Skip to next descriptor
                }
            };
            println!("DLL: {}", dll_name);

            // Get the IAT and INT (Import Name Table)
            let iat = match desc.iat() {
                Ok(iat) => iat,
                Err(e) => {
                    println!("Error getting IAT for {}: {:?}", dll_name, e);
                    continue; // Skip to next descriptor
                }
            };

            let names = match desc.int() {
                Ok(names) => names,
                Err(e) => {
                    println!("Error getting INT for {}: {:?}", dll_name, e);
                    continue; // Skip to next descriptor
                }
            };

            // Zip the IAT virtual addresses with their corresponding import entries
            for (va, entry) in iat.zip(names) {
                match entry {
                    Ok(import) => match import {
                        Import::ByName { name, .. } => {
                            println!("  Import: {} at VA: {:#x}", name, va);

                            self.iat_dict.insert(name.to_string(), (*va as u64, dll_name.to_string()));
                        }
                        pelite::pe::imports::Import::ByOrdinal { ord } => {
                            println!("  Ordinal: {} at VA: {:#x}", ord, va)
                        }
                    },
                    Err(e) => println!("  Error: {:?}", e),
                }
            }
        }

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