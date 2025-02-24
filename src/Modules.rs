// Modules
use crate::Module;
use Module::*;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HMODULE};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Module32First, Module32FirstW, Module32Next, Module32NextW, MODULEENTRY32, MODULEENTRY32W, TH32CS_SNAPMODULE};
use windows::core::{Error, Result};
use std::ptr::null_mut;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use crate::is_valid_process_handle;
use crate::utils::get_process_handle;

/// Holds a collection of module objects.
pub struct modules {
    pub modules: Vec<Module::module>,
    cumulative_module_sizes: Vec<u32>,
    cumulative_module_size: u32,
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


        Module32First(snapshot, &mut entry).unwrap();

        let overall_bytes_read = 0;
        let mut index = 0;

        loop {


            // Capture module data
            let base_address = entry.modBaseAddr;
            let module_size = entry.modBaseSize as usize;
            let path = entry.szExePath;

            let mut this_module = module::new(base_address as u32, module_size as u32, index, path);

            self.cumulative_module_size += module_size as u32;
            self.cumulative_module_sizes.push(module_size as u32);

            // Allocate buffer for module data
            let mut buffer = vec![0u8; module_size];
            let mut bytes_read = 0;

            // Read process memory
            let result =
                ReadProcessMemory(
                    process_handle,
                    base_address as _,
                    buffer.as_mut_ptr() as _,
                    module_size,
                    Some(&mut bytes_read)
                );
            println!("bytes_read: {}", bytes_read);
            if result.is_ok() {
                buffer.truncate(bytes_read); // Adjust buffer to bytes actually read
                this_module.dirty_data = Some(buffer);
                index += 1;
                this_module.valid = Some(true);
                self.modules.push(this_module);
            } else {
                let err = unsafe { GetLastError() };
                eprintln!("Failed to read module at {base_address:p}: {}", Error::from(err));
                index += 1;
                this_module.valid = Some(false);
                self.modules.push(this_module);
            }
            // Move to next module
            match unsafe { Module32Next(snapshot, &mut entry) } {
                Ok(_) => continue,
                Err(_) => break,
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