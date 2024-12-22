use std::slice;
use std::ffi::{c_void, CStr, CString};
use std::ptr::{null, null_mut, read};
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
            Diagnostics::Debug::{
                sfMax,
                ReadProcessMemory
            },
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

const COMPARE_LENGTH: usize = 20;
const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x00000002;
const LOAD_LIBRARY_AS_IMAGE_RESOURCE: u32 = 0x00000020;

// function to get the pid of a process with a given name
fn get_pid(process_name: &str) -> std::result::Result<u32, Error> {
    unsafe {
        // create a snapshot of all the processes
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(Error::from_win32());
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

        Err(Error::from_win32())
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
fn get_remote_module_base(process_handle: HANDLE, module_name: &str, pid: u32) -> Result<Option<usize>> {
    unsafe {
        // Create a snapshot of the modules in the process
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)?;
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(Error::from_win32());
        }

        // Initialise the module entry
        let mut module_entry = MODULEENTRY32 {
            dwSize: std::mem::size_of::<MODULEENTRY32>() as u32,
            ..Default::default()
        };

        // Iterate through modules to find the target module
        if Module32First(snapshot, &mut module_entry).is_ok() {
            loop {
                let module_name_current = CStr::from_ptr(module_entry.szModule.as_ptr());
                if let Ok(name) = module_name_current.to_str() {
                    if name.eq_ignore_ascii_case(module_name) {
                        // Module found, return its base address
                        println!("Module found: {} at base address: {:#x}", name, module_entry.modBaseAddr as usize);
                        return Ok(Some(module_entry.modBaseAddr as usize));
                    }
                }
                // Move to the next module in the snapshot
                if Module32Next(snapshot, &mut module_entry).is_err() {
                    break;
                }
            }
        }

        // If the module wasn't found
        Err(Error::from_win32())
    }
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

fn check_function_in_module(function_address: usize, module_info: MODULEINFO)->bool{
    // Get the base address of the module
    let module_base = module_info.lpBaseOfDll as usize;

    // Get the size of the module's memory region
    let mod_size = module_info.SizeOfImage as usize;

    // Check if the function's address is within the bounds of the module
    if function_address >= module_base && function_address < (module_base + mod_size) {
        true
    } else {
        false
    }
}

// function to get the address of a given function from a dirty process
fn get_dirty_function_address(process_handle: HANDLE, module_name: &str, function_name: &str, pid: u32) -> std::result::Result<Option<usize>, Error> {
    unsafe {
        // Step 1 : get the base address of the module in the target process
        let remote_module_base = get_remote_module_base(process_handle, module_name, pid).unwrap().unwrap();

        // get the local handle of the module
        let module_name_cstr = CString::new(module_name).unwrap();
        let module_handle_result = GetModuleHandleA(PCSTR(module_name_cstr.as_ptr() as *const u8));
        if !module_handle_result.is_ok() {
            return Err(Error::from_win32());
        }

        // unwrap the module handle from the result
        let module_handle = module_handle_result?;

        // get the function name as a c string for PCSTR
        let function_name_cstr = CString::new(function_name).unwrap();


        // get the local address of the function in the current process
        let local_function_address = GetProcAddress(module_handle, PCSTR(function_name_cstr.as_ptr() as *const u8));
        if local_function_address.is_none() {
            return Ok(None);
        }

        // Step 2: Get the module information from the target process
        let module_info: MODULEINFO = get_module_info(module_handle, process_handle)?;

        // Step 2: Calculate the offset of the function in the local process
        let function_offset = local_function_address.unwrap() as usize - module_info.lpBaseOfDll as usize;

        // Step 3: Calculate the absolute address of the function in the remote process
        let remote_function_address = remote_module_base + function_offset;

        Ok(Some(remote_function_address))  // Return the calculated absolute address
    }
}


unsafe fn read_process_memory(process_handle: HANDLE, address: usize, size: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; size];
    let mut bytes_read: usize = 0;

    match ReadProcessMemory(
        process_handle,
        address as *const c_void,
        buffer.as_mut_ptr() as *mut c_void,
        size,
        Some(&mut bytes_read),
    ) {
        Ok(_) => {
            // Check if all bytes were read
            if bytes_read != size {
                panic!("Only part of the memory was read. Expected {} bytes, but got {}.", size, bytes_read);
            }
            buffer
        },
        Err(e) => {
            panic!("Failed to read process memory: {}", e);
        }
    }
}

fn print_prologue_bytes(prologue: Vec<u8>) {
    println!("Function Prologue (First {} Bytes):", prologue.len());
    for byte in &prologue {
        print!("{:02x} ", byte);
    }
    println!();
}

unsafe fn inline(process: &str, module: &str, function: &str){
    let pid_result = get_pid(&process).unwrap();

    let handle = get_handle(pid_result).unwrap();

    let dirty_function_address = get_dirty_function_address(handle, &module, &function, pid_result).unwrap().unwrap();

    let data = read_process_memory(handle, dirty_function_address, COMPARE_LENGTH);

    print_prologue_bytes(data);

    check_process_handle(handle).unwrap();
}


fn main() {
    unsafe { inline("msedge.exe", "kernel32.dll", "CopyFileW"); }
}