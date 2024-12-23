use std::ffi::{c_void, CStr, CString};
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
                PROCESS_ACCESS_RIGHTS,
                PROCESS_BASIC_INFORMATION
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
fn get_process_handle(process_id: u32) -> Result<HANDLE> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_ALL_ACCESS, false, process_id)?;
        if process_handle == INVALID_HANDLE_VALUE {
            return Err(Error::from_win32());
        }
        Ok(process_handle)
    }
}

// function to retrieve a module base address in the dirty process
fn get_module_handle(module_name: &str, pid: u32) -> Result<Option<HMODULE>> {
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
                let module_name_current = CStr::from_ptr(module_entry.szModule.as_ptr());
                if let Ok(name) = module_name_current.to_str() {
                    println!("Found module: {} at base address: {:#x}, handle: {:?}", name, module_entry.modBaseAddr as usize, module_entry.hModule);
                } else {
                    println!("Failed to convert module name to string.");
                }

                // Check if the current module matches the target module name
                if let Ok(name) = module_name_current.to_str() {
                    if name.eq_ignore_ascii_case(module_name) {
                        // Module found, return its handle
                        println!("Module found: {} with handle: {:?}", name, module_entry.hModule);
                        return Ok(Some(module_entry.hModule)); // Return the module handle as usize
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

fn get_module_base_address(module_name: &str, pid: u32) -> Result<Option<usize>> {
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
                let module_name_current = CStr::from_ptr(module_entry.szModule.as_ptr());
                if let Ok(name) = module_name_current.to_str() {
                    println!("Found module: {} at base address: {:#x}, handle: {:?}", name, module_entry.modBaseAddr as usize, module_entry.hModule);
                } else {
                    println!("Failed to convert module name to string.");
                }

                // Check if the current module matches the target module name
                if let Ok(name) = module_name_current.to_str() {
                    if name.eq_ignore_ascii_case(module_name) {
                        // Module found, return its base address
                        println!("Module found: {} with base address: {:#x}", name, module_entry.modBaseAddr as usize);
                        return Ok(Some(module_entry.modBaseAddr as usize)); // Return the base address as usize
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
    let result = GetModuleInformation(process_handle, module_handle, &mut module_info, size_of::<MODULEINFO>() as u32);

    if result.is_ok() {
        Ok(module_info) // Return module info if successful
    } else {
        Err(Error::from_win32()) // Return error if failed
    }
}

// function to get the address of a given function from a dirty process
fn get_function_address(process_handle: HANDLE, module_name: &str, function_name: &str, pid: u32) -> std::result::Result<Option<usize>, Error> {
    unsafe {

        //STEP 1: GET FUNCTION OFFSET

        // unwrap the module handle from the result
        let module_handle = match get_module_handle(module_name, pid)? {
            Some(handle) => handle,
            None => return Err(Error::from_win32()), // or similar error
        };

        // get the function name as a c string for PCSTR
        let function_name_cstr = CString::new(function_name).unwrap();


        // get the offset local address of the function
        let local_function_address = GetProcAddress(module_handle, PCSTR(function_name_cstr.as_ptr() as *const u8));
        if local_function_address.is_none() {
            return Ok(None);
        }

        let static_module_info = get_module_info(module_handle, process_handle)?;
        let static_module_base = static_module_info.lpBaseOfDll as usize;

        let function_offset = local_function_address.unwrap() as usize - static_module_base;

        //STEP 2: GET MODULE BASE ADDRESS

        let module_base_address = get_module_base_address(module_name, pid)?.unwrap();

        //STEP 3: CALCULATE

        let remote_function_address = module_base_address + function_offset;

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
    let process_handle = get_process_handle(pid_result).unwrap();
    let dirty_function_address = get_function_address(process_handle, &module, &function, pid_result).unwrap().unwrap();

    let data = read_process_memory(process_handle, dirty_function_address, COMPARE_LENGTH);
    print_prologue_bytes(data);

}


fn main() {
    unsafe { inline("msedge.exe", "kernel32.dll", "CopyFileW"); }
}