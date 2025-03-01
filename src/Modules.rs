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
    cumulative_module_sizes: Vec<u64>,
    cumulative_module_size: u64,
}

impl modules {
    /// Enumerate modules in the target process.

    pub fn new() -> Self {
        Self {
            modules: Vec::new(),                 // Empty vector for modules
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
        let mut index= 0;

        //loop to iterate through the modules
        loop {

            // Capture module data
            let base_address = entry.modBaseAddr as u64;
            let module_size = entry.modBaseSize as usize;
            let end_address = base_address + module_size as u64;
            let path = entry.szExePath;

            //set current address to base address for the start of the module so it can iterate through pages
            let mut current_address = base_address;

            self.cumulative_module_size += module_size as u64;
            self.cumulative_module_sizes.push(module_size as u64);

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
                    let offset = (current_address - base_address) as usize;
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

            print!("bytes_read: {}", total_bytes_read);
            print!(" Module size: {}", module_size);
            println!(" for index: {}", index);
            //println!("pages valid: {:?}", pages_valid);

            //make module object
            let mut this_module = module::new(base_address, module_size as u64, index, entry.szExePath);

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
}