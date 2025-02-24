// modules.rs

use windows::Win32::Foundation::{HANDLE, HMODULE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
};
use windows::core::Result;
use crate::base_modules::module;
use std::ptr::null_mut;

/// Holds a collection of module objects.
pub struct Modules {
    pub modules: Vec<module>,
}

impl Modules {
    /// Enumerate modules in the target process.
    pub fn load_modules(process_id: u32, process_handle: HANDLE) -> Result<Self> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id)? };
        let mut module_entry = MODULEENTRY32W::default();
        module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        let mut modules = Vec::new();

        let mut success = unsafe { Module32FirstW(snapshot, &mut module_entry).as_bool() };
        while success {
            // Convert module_entry.szModule (WCHAR array) to Rust String.
            let filename = String::from_utf16_lossy(&module_entry.szModule);
            // Create a ModuleInfo instance.
            let module_info = ModuleInfo::new(process_handle, HMODULE(module_entry.hModule as _))
                .unwrap_or_else(|_| ModuleInfo {
                    base_address: module_entry.modBaseAddr as usize,
                    virtual_size: module_entry.modBaseSize as usize,
                    filename: filename.clone(),
                    hmodule: HMODULE(module_entry.hModule as _),
                    raw_image: Vec::new(),
                });
            modules.push(module_info);
            success = unsafe { Module32NextW(snapshot, &mut module_entry).as_bool() };
        }
        // (Remember to close the snapshot handle if needed)
        Ok(Self { modules })
    }

    /// Retrieve a module by (partial) filename.
    pub fn get_module(&self, name: &str) -> Option<&ModuleInfo> {
        self.modules.iter().find(|m| m.filename.to_lowercase().contains(&name.to_lowercase()))
    }

    pub fn clean(&mut self) {
        self.modules.clear();
    }

    pub fn all_modules(&self) -> &Vec<ModuleInfo> {
        &self.modules
    }
}