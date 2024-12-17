use std::slice;
use std::ffi::{c_void, CStr};
use windows::{
    core::*,
    Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32, TH32CS_SNAPPROCESS, Process32First, Process32Next},
    Win32::System::Diagnostics::Debug::sfMax,
    Win32::System::LibraryLoader::{LoadLibraryExA, GetModuleHandleA, GetProcAddress, LOAD_LIBRARY_FLAGS},
    Win32::Foundation::{HMODULE, INVALID_HANDLE_VALUE, E_FAIL, CloseHandle, HANDLE},
    Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, GetExitCodeProcess},
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

fn get_handle(pid: u32) -> Result<HANDLE> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)?;
        if process_handle == INVALID_HANDLE_VALUE {
            return Err(Error::from_win32());
        }
        Ok(process_handle)
    }
}

fn check_process_handle(handle: HANDLE) -> Result<()> {
    unsafe {
        // Check if the handle is valid by querying the exit code of the process
        let mut exit_code = 0;
        if GetExitCodeProcess(handle, &mut exit_code).is_ok() {
            if exit_code != 259 { // 259 indicates the process is still running
                println!("Process exited with code: {}", exit_code);
            } else {
                println!("Process is still running.");
            }
        } else {
            return Err(Error::from_win32());
        }
    }

    Ok(())
}

fn main() {
    // Example PID for testing
    let pid_result = get_pid("msedge.exe").unwrap().unwrap();

    match get_handle(pid_result) {
        Ok(handle) => {
            println!("Successfully obtained handle: {:?}", handle);

            // Check if the process handle is valid
            if let Err(e) = check_process_handle(handle) {
                eprintln!("Failed to check handle: {:?}", e);
            }

            // Remember to close the handle when done
            unsafe {
                CloseHandle(handle);
                println!("Handle closed.");
            }
        }
        Err(e) => {
            eprintln!("Error getting handle: {:?}", e);
        }
    }
}