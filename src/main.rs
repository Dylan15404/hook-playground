use std::slice;
use std::ffi::{c_void, CStr};
use windows::{
    core::*,
    Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32, TH32CS_SNAPPROCESS, Process32First, Process32Next},
    Win32::System::Diagnostics::Debug::sfMax,
    Win32::System::LibraryLoader::{LoadLibraryExA, GetModuleHandleA, GetProcAddress, LOAD_LIBRARY_FLAGS},
    Win32::Foundation::{HMODULE, INVALID_HANDLE_VALUE, E_FAIL, CloseHandle, HANDLE},
    Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION},
};
const COMPARE_LENGTH: usize = 14;
const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x00000002;
const LOAD_LIBRARY_AS_IMAGE_RESOURCE: u32 = 0x00000020;


fn get_pid(process_name: &str) -> Result<Option<u32>> {
    unsafe {
        // Create a snapshot of all the processes
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(windows::core::Error::from_win32());
        }

        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        // Start enumerating processes
        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                // Check if the current process name matches the target process name
                let exe_name = CStr::from_ptr(entry.szExeFile.as_ptr()).to_string_lossy();
                if exe_name.to_lowercase() == process_name.to_lowercase() {
                    // Found the process, return its PID
                    return Ok(Some(entry.th32ProcessID));
                }


                // Move to the next process
                if !Process32Next(snapshot, &mut entry).is_ok() {
                    break;
                }
            }
        }

        Err(windows::core::Error::from_win32())
    }
}


fn main() {
    // Example code:

    // processes to look for
    let processes_to_check = vec!["notepad.exe", "msedge.exe", "cmd.exe"];

    for process_name in processes_to_check {
        match get_pid(process_name) {
            Ok(Some(pid)) => println!("Process '{}' found with PID: {}", process_name, pid),
            Ok(None) => println!("Process '{}' not found", process_name),
            Err(e) => println!("Error occurred while searching for '{}': {:?}", process_name, e),
        }
    }

    // Additional test for a process that doesn't exist
    match get_pid("thisprocessdoesntexist.exe") {
        Ok(Some(_)) => println!("Unexpectedly found a nonexistent process!"),
        Ok(None) => println!("As expected, 'thisprocessdoesntexist.exe' was not found"),
        Err(e) => println!("Error occurred while searching for a nonexistent process: {:?}", e),
    }
}