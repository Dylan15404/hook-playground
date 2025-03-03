use std::collections::HashMap;
use std::io::ErrorKind;
use std::ops::Index;
// Modules
use crate::Module;
use Module::*;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HMODULE};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Module32First, Module32FirstW, Module32Next, Module32NextW, MODULEENTRY32, MODULEENTRY32W, TH32CS_SNAPMODULE};
use windows::core::{Error, Result};
use std::ptr::null_mut;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use crate::is_valid_process_handle;
use crate::utils::get_process_handle;

/// Holds a collection of module objects.
pub struct modules {
    pub modules: Vec<Module::module>,
    pub function_hashes: HashMap<String, u64>,
    cumulative_module_sizes: Vec<u64>,
    cumulative_module_size: u64,
}

impl modules {
    /// Enumerate modules in the target process.

    pub fn new() -> Self {
        Self {
            modules: Vec::new(),                 // Empty vector for modules
            function_hashes: HashMap::new(),
            cumulative_module_sizes: Vec::new(), // Empty vector for sizes
            cumulative_module_size: 0,           // Default to 0
        }
    }


pub unsafe fn load_modules(&mut self, pid: u32){
        let process_handle = get_process_handle(pid).unwrap();
        println!("handle valid: {}", is_valid_process_handle(process_handle));

        // Create a snapshot of the modules in the process
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid).unwrap();
        println!("Creating snapshot for PID: {}", pid);
        println!("Snapshot handle: {:?}", snapshot);

        // Initialize the module entry structure
        let mut entry = MODULEENTRY32 {
            dwSize: size_of::<MODULEENTRY32>() as u32,
            ..Default::default()
        };
        println!("Module entry size: {}", size_of::<MODULEENTRY32>());

        // Get system page size
        let mut system_info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut system_info);
        let page_size = system_info.dwPageSize as usize;


        Module32First(snapshot, &mut entry).unwrap();

        let overall_bytes_read = 0;
        let mut index: u16= 0;

        let process_base = entry.modBaseAddr as u64;
        let cumulative_module_size: u64 = 0;

    //loop to iterate through the modules
        loop {

            // Capture module data
            let module_base = entry.modBaseAddr as u64;
            let module_size = entry.modBaseSize as usize;
            let end_address = module_base + module_size as u64;
            let path = entry.szExePath;

            //set current address to base address for the start of the module so it can iterate through pages
            let mut current_address = module_base;


            self.cumulative_module_size += module_size as u64;
            if index == 0 { self.cumulative_module_sizes.push(module_size as u64) } else {
                let value = self.cumulative_module_sizes[index as usize - 1] + module_size as u64;
                self.cumulative_module_sizes.push(value);
            }

            let mut pages_valid: Vec<bool> = Vec::new();

            // Allocate buffer for module data
            let mut buffer = vec![0u8; module_size];
            let mut total_bytes_read = 0;

            //loop to iterate through the pages
            while current_address < end_address {

                //page buffer the lower of remaining or page_size to make sure it doesn't read over the boundary
                let remaining = end_address - current_address;
                let read_size = std::cmp::min(remaining, page_size as u64);
                let mut page_buffer = vec![0u8; read_size as usize];

                let mut bytes_read = 0;

                // Read process memory
                let result =
                    ReadProcessMemory(
                        process_handle,
                        current_address as _,
                        page_buffer.as_mut_ptr() as _,
                        read_size as usize,
                        Some(&mut bytes_read)
                    );


                if result.is_ok() {
                    let offset = (current_address - module_base) as usize;
                    buffer[offset..offset + bytes_read].copy_from_slice(&page_buffer);
                    total_bytes_read += bytes_read;
                    pages_valid.push(true);
                } else {
                    let err = unsafe { GetLastError() };
                    eprintln!("Failed page @ {current_address}: {} ({} bytes read)",
                              Error::from(err),
                              bytes_read
                    );
                    pages_valid.push(false);
                }
                current_address += read_size;
            }

            println!("bytes_read: {}", total_bytes_read);
            println!("Module size: {}", module_size);
            println!("Base address: {}", module_base);
            println!("For index: {}", index);
            println!("/////////////////////////////////");

            //println!("pages valid: {:?}", pages_valid);

            //make module object
            let mut this_module = module::new(process_base, module_base, module_size as u64, index, entry.szExePath);

            this_module.dirty_data = Some(buffer);
            this_module.valid = Some(total_bytes_read > 0);
            this_module.pages_valid = pages_valid;
            self.modules.push(this_module);

            match Module32Next(snapshot, &mut entry) {
                Ok(_) => index += 1,
                Err(e) => {
                    println!("Finished processing {} modules", index + 1);
                    break;
                }
            }
        }


        if let Err(e) = CloseHandle(snapshot) {
            eprintln!("Failed to close snapshot handle: {}", e);
        }
        if let Err(e) = CloseHandle(process_handle) {
            eprintln!("Failed to close process handle: {}", e);
        }
        println!("Loaded {} modules from memory", self.modules.len());
}

    /// Retrieve a module by (partial) filename.
    // pub fn get_module(&self, name: &str) -> Option<&module> {
    //     self.modules.iter().find(|m| m.filename.to_lowercase().contains(&name.to_lowercase()))
    // }

    pub fn clean(&mut self) {
        self.modules.clear();
    }

    pub fn all_modules(&self) -> &Vec<module> {
        &self.modules
    }

    pub fn read_modules(&mut self) -> Result<()> {
        for module in &mut self.modules {
            println!("reading module: {:?} at index: {}", module.name, module.index);
            if module.valid.unwrap() {
                match module.read_header() {
                    Ok(()) => {
                        for entry in &module.iat_dict {
                            println!("module: {}, from {}, va {}", entry.0, entry.1.0, entry.1.1);
                        }
                    }
                    Err(e) => {
                        println!("Failed to read header for module {:?} at index {}: {}",
                                 module.name, module.index, e);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn find_function_location(&self, rva: u64) -> Result<(u16, u64)> {
        for (index, &size) in self.cumulative_module_sizes.iter().enumerate() {
            println!("rva: {}, Index: {}, Size: {}, rva < size: {}",rva, index, size, rva < size);
            while rva < size {
                if index == 0 {
                    return Ok((0, rva));
                }
                let last = self.cumulative_module_sizes[index - 1];
                let remainder = rva - last;
                return Ok((index as u16, remainder));
            }
        }
        let err = unsafe { GetLastError() };
        eprintln!("Function lookup failed with error: {:?}", err);
        Err(err)?
    }


}