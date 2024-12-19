use std::slice;
use std::ffi::{c_void, CStr, CString};
use std::ptr::{null, null_mut};
use windows::{
    core::*,
    Win32::{
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot,
                PROCESSENTRY32,
                MODULEENTRY32,
                TH32CS_SNAPPROCESS,
                TH32CS_SNAPMODULE,
                Process32First,
                Process32Next,
                Module32First,
                Module32Next
            },
            Threading::{
                OpenProcess,
                PROCESS_ALL_ACCESS,
                PROCESS_QUERY_INFORMATION,
                PROCESS_VM_READ,
                GetExitCodeProcess,
                PROCESS_ACCESS_RIGHTS
            },
            Diagnostics::Debug::sfMax,
            LibraryLoader::{
                LoadLibraryExA,
                GetModuleHandleA,
                GetProcAddress,
                LOAD_LIBRARY_FLAGS
            },
            ProcessStatus::{
                MODULEINFO,
                GetModuleInformation
            },

        },
        Foundation::{
            HMODULE,
            INVALID_HANDLE_VALUE,
            E_FAIL,
            CloseHandle,
            HANDLE
        },
    }
};

const COMPARE_LENGTH: usize = 14;
const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x00000002;
const LOAD_LIBRARY_AS_IMAGE_RESOURCE: u32 = 0x00000020;

// function to get the pid of a process with a given name
fn get_pid(process_name: &str) -> std::result::Result<u32, Error> {
    unsafe {
        // create a snapshot of all the processes
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(windows::core::Error::from_win32());
        }

        // initialise the process entry
        let mut process_entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
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

        Err(windows::core::Error::from_win32())
    }
}

// function to get the handle of a process with a given pid
fn get_handle(pid: u32) -> std::result::Result<HANDLE, Error> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_ALL_ACCESS, false, pid)?;
        if process_handle == INVALID_HANDLE_VALUE {
            return Err(Error::from_win32());
        }
        Ok(process_handle)
    }
}

fn check_process_handle(handle: HANDLE) -> Result<()> {
    unsafe {
        // check if the handle is valid by querying the exit code of the process
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

// function to retrieve a module base address in the dirty process
fn get_module_base_address(process_handle: HANDLE, module_name: &str, pid: u32) -> std::result::Result<Option<usize>, Error> {
    unsafe {
        // Create a snapshot of the modules in the process
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)?;
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(windows::core::Error::from_win32());
        }

        // initialise the module entry
        let mut module_entry = MODULEENTRY32 {
            dwSize: std::mem::size_of::<MODULEENTRY32>() as u32,
            ..Default::default()
        };


        // iterate through modules to find the target module
        if Module32First(snapshot, &mut module_entry).is_ok() {
            loop {
                let module_name_current = std::ffi::CStr::from_ptr(module_entry.szModule.as_ptr()); // this on is different
                if let Ok(name) = module_name_current.to_str() {
                    if name.eq_ignore_ascii_case(module_name) {
                        return Ok(Some(module_entry.modBaseAddr as usize));
                    }
                }
                if !Module32Next(snapshot, &mut module_entry).is_ok() {
                    break;
                }
            }
        }
    }
    Err(windows::core::Error::from_win32())
}

// function to get module information (base address, size, etc.)
unsafe fn get_module_info(module_handle: HMODULE, process_handle: HANDLE) -> std::result::Result<MODULEINFO, Error> {
    // Attempt to retrieve module information
    let mut module_info = MODULEINFO::default(); // Default initialization
    let result = GetModuleInformation(process_handle, module_handle, &mut module_info, std::mem::size_of::<MODULEINFO>() as u32);

    if result.is_ok() {
        Ok(module_info) // Return module info if successful
    } else {
        Err(Error::from_win32()) // Return error if failed
    }
}

// function to get the address of a given function from a dirty process
fn get_dirty_function_address(process_handle: HANDLE, module_name: &str, function_name: &str, pid: u32) -> std::result::Result<Option<usize>, Error> {
    unsafe {
        // get the base address of the module in the target process
        let module_base = get_module_base_address(process_handle, module_name, pid)?;

        // get the local handle of the module
        let module_name_cstr = CString::new(module_name).unwrap();
        let module_handle_result = GetModuleHandleA(PCSTR(module_name_cstr.as_ptr() as *const u8));
        if !module_handle_result.is_ok() {
            return Err(windows::core::Error::from_win32());
        }

        // unwrap the module handle from the result
        let module_handle = module_handle_result?;

        // get the function name as a c string for PCSTR
        let function_name_cstr = CString::new(function_name).unwrap();


        // get the local address of the function in the current process
        let local_proc_address = GetProcAddress(module_handle, PCSTR(function_name_cstr.as_ptr() as *const u8));
        if local_proc_address.is_none() {
            return Ok(None);
        }

        // calculate the offset of the function within the module
        let module_info: MODULEINFO = get_module_info(module_handle, process_handle)?;

        // get function offset from the module base to the function start
        let function_offset = local_proc_address.unwrap() as usize - module_info.lpBaseOfDll as usize;

        // calculate the offset of the function within the module
        let target_function_address_offset = module_base.unwrap() as usize + function_offset;

        // calculate the remote address of the function
        Ok(Some(target_function_address_offset))
    }
}

fn print_function_ascii(function_address: usize, num_bytes: usize) {
    // ensure the pointer is valid for reading.
    let function_ptr = function_address as *const u8;

    if function_ptr.is_null() {
        eprintln!("The function pointer is null.");
        return;
    }

    unsafe {
        // create a slice from the raw pointer
        let function_bytes = slice::from_raw_parts(function_ptr, num_bytes);

        // convert and print bytes as ASCII characters
        println!("First {} bytes of the function at address {:#x} (as ASCII):", num_bytes, function_address);
        for &byte in function_bytes {
            let char_representation = if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
                byte as char
            } else {
                '.' // replace non-printable bytes with a dot
            };
            print!("{}", char_representation);
        }
        println!(); // print a newline at the end
    }
}

fn main() {
    let pid_result = get_pid("msedge.exe").unwrap();

    let handle = get_handle(pid_result).unwrap();

    let module_base_address = get_module_base_address(handle, "kernel32.dll", pid_result).unwrap();

    let dirty_function_address = get_dirty_function_address(handle, "kernel32.dll", "CopyFileW", pid_result).unwrap().unwrap();

    print_function_ascii(dirty_function_address, 100);

    check_process_handle(handle).unwrap();
}