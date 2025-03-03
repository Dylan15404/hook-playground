use std::ffi::{CStr, CString};
use pelite::pe::Va;
use winapi::ctypes::c_void;
use windows::core::{Error, PCSTR};
use windows::Win32::Foundation::{CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_PROTECT_FROM_CLOSE, HMODULE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Module32First, Module32Next, Process32First, Process32Next, MODULEENTRY32, PROCESSENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS};
use windows::Win32::System::LibraryLoader::LoadLibraryA;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

// function to get the pid of a process with a given name
pub(crate) fn get_pid(process_name: &str) -> Result<u32, Error> {
    unsafe {
        // create a snapshot of all the processes
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(Error::from_win32());
        }

        // initialise the process entry
        let mut process_entry = PROCESSENTRY32 {
            dwSize: size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        // enumerate processes in snapshot
        if Process32First(snapshot, &mut process_entry).is_ok() {
            loop {
                // check if the current process name matches the target process name
                let exe_name = CStr::from_ptr(process_entry.szExeFile.as_ptr()).to_string_lossy();
                if exe_name.eq_ignore_ascii_case(process_name) {
                    // found the process, return its PID
                    return Ok(process_entry.th32ProcessID);
                }

                // move to the next process
                if !Process32Next(snapshot, &mut process_entry).is_ok() {
                    break;
                }
            }
        }

        Err(Error::from_win32())
    }
}

// function to get the handle of a process with a given pid
pub(crate) fn get_process_handle(process_id: u32) -> windows::core::Result<HANDLE> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_id)?;
        if (process_handle == INVALID_HANDLE_VALUE) {
            return Err(Error::from_win32());
        }
        SetHandleInformation(process_handle, HANDLE_FLAG_PROTECT_FROM_CLOSE.0, HANDLE_FLAG_PROTECT_FROM_CLOSE)?;
        Ok(process_handle)
    }
}

// function to retrieve a module base address in the dirty process
pub(crate) fn get_running_module_handle(module_name: &str, pid: u32) -> windows::core::Result<Option<HMODULE>> {
    unsafe {
        // Create a snapshot of the modules in the process
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)?;
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(Error::from_win32());
        }

        println!("Creating snapshot for PID: {}", pid);
        println!("Snapshot handle: {:?}", snapshot);

        // Initialize the module entry structure
        let mut module_entry = MODULEENTRY32 {
            dwSize: size_of::<MODULEENTRY32>() as u32,
            ..Default::default()
        };
        println!("Module entry size: {}", size_of::<MODULEENTRY32>());

        // Iterate through modules to find the target module
        if Module32First(snapshot, &mut module_entry).is_ok() {
            loop {
                // Convert the current module name to a string once and store it
                let module_name_current = CStr::from_ptr(module_entry.szModule.as_ptr());
                if let Ok(name) = module_name_current.to_str() {
                    println!("Found module: {} at base address: {:#x}, handle: {:?}", name, module_entry.modBaseAddr as usize, module_entry.hModule);

                    // Check if the current module matches the target module name
                    if name.eq_ignore_ascii_case(module_name) {
                        // Module found, return its handle
                        println!("Module found: {} with handle: {:?}", name, module_entry.hModule);
                        // Close the snapshot handle before returning
                        CloseHandle(snapshot);
                        return Ok(Some(module_entry.hModule)); // Return the module handle
                    }
                } else {
                    println!("Failed to convert module name to string.");
                }

                // Move to the next module in the snapshot
                if Module32Next(snapshot, &mut module_entry).is_err() {
                    break;
                }
            }
        }

        // Close the snapshot handle if we exit the loop without finding the module
        CloseHandle(snapshot);

        // If the module wasn't found
        Err(Error::from_win32())
    }
}

pub(crate) fn get_static_module_handle(module_name: &str) -> windows::core::Result<Option<HMODULE>> {
    unsafe {
        let module_name_cstr = CString::new(module_name).unwrap();
        let module_handle_result = LoadLibraryA(PCSTR(module_name_cstr.as_ptr() as *const u8));

        // Check if module_handle is valid
        let module_handle = module_handle_result?;
        if !module_handle.is_invalid() {
            Ok(Some(module_handle)) // Successfully loaded
        } else {
            // Return an error if LoadLibraryA failed
            return Err(Error::from_win32());
        }
    }
}