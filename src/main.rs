use std::ffi::{c_void, CStr, CString, OsString};
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use std::ptr::null_mut;
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
                Module32Next,
                Module32FirstW,
                Module32NextW,
                MODULEENTRY32W
            },
            Threading::{
                OpenProcess,
                PROCESS_ALL_ACCESS,
                PROCESS_QUERY_INFORMATION,
                PROCESS_VM_READ,
                GetExitCodeProcess,
                PROCESS_ACCESS_RIGHTS,
                PROCESS_BASIC_INFORMATION,
                GetCurrentProcess
            },
            Diagnostics::Debug::{
                sfMax,
                ReadProcessMemory,
                IMAGE_SECTION_HEADER,
                IMAGE_FILE_HEADER,
                IMAGE_OPTIONAL_HEADER64,
                IMAGE_NT_HEADERS64,
                IMAGE_DATA_DIRECTORY,
                IMAGE_DIRECTORY_ENTRY_EXPORT
            },
            LibraryLoader::{
                LoadLibraryExA,
                GetModuleHandleA,
                GetProcAddress,
                LOAD_LIBRARY_FLAGS
            },
            ProcessStatus::{
                MODULEINFO,
                GetModuleInformation,
                GetMappedFileNameA,
                EnumProcessModules,
                GetModuleBaseNameW
            },
            LibraryLoader::{
                LoadLibraryA
            },
            SystemServices::{
                IMAGE_EXPORT_DIRECTORY,
                IMAGE_DOS_HEADER
            },
            Memory::{
                MEMORY_BASIC_INFORMATION
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
use windows::Win32::System::Memory::VirtualQuery;

const COMPARE_LENGTH: usize = 20;
const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x00000002;
const LOAD_LIBRARY_AS_IMAGE_RESOURCE: u32 = 0x00000020;
const MAX_MODULE_NAME: usize = 256;


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
fn get_process_handle(process_id: u32, access:  PROCESS_ACCESS_RIGHTS) -> Result<HANDLE> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_ALL_ACCESS, false, process_id)?;
        if process_handle == INVALID_HANDLE_VALUE {
            return Err(Error::from_win32());
        }
        Ok(process_handle)
    }
}

// function to retrieve a module base address in the dirty process
fn get_running_module_handle(module_name: &str, pid: u32) -> Result<Option<HMODULE>> {
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

fn get_static_module_handle(module_name: &str) -> Result<Option<HMODULE>> {
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


fn get_module_base_address(target_module: &str, pid: u32) -> Result<usize> {
    unsafe {
        // Create a snapshot of the modules in the process
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)?;
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(Error::from_win32());
        }

        println!("Creating snapshot for PID: {}", pid);
        println!("Snapshot handle: {:?}", snapshot);

        // Initialize the module entry structure
        let mut module_entry: MODULEENTRY32W = std::mem::zeroed();
        module_entry.dwSize = size_of::<MODULEENTRY32W>() as u32;

        println!("Module entry size: {}", size_of::<MODULEENTRY32>());

        // Iterate modules
        let mut found = false;
        let mut base_addr = 0usize;

        if Module32FirstW(snapshot, &mut module_entry).is_ok() {
            loop {
                // Extract module name
                let name_wide = &module_entry.szModule;
                let name_len = name_wide.iter().position(|&c| c == 0).unwrap_or(name_wide.len());
                let name = OsString::from_wide(&name_wide[..name_len]).to_string_lossy().into_owned();

                // Case-insensitive comparison
                if name.eq_ignore_ascii_case(target_module) {
                    base_addr = module_entry.modBaseAddr as usize;
                    found = true;
                    break;
                }

                if Module32NextW(snapshot, &mut module_entry).is_err() {
                    break;
                }
            }
        } else {
            return Err(Error::from_win32()); // Return error if failed
        }

        if found {
            Ok(base_addr)
        } else {
            return Err(Error::from_win32()) // Return error if failed
        }
    }
}

// function to get module information (base address, size, etc.)
unsafe fn get_module_info(module_handle: HMODULE, process_handle: HANDLE) -> Result<MODULEINFO> {
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

unsafe fn get_function_address(module_handle: HMODULE, target_function: &str) -> Result<usize> {
    let func_name: PCSTR = PCSTR::from_raw(target_function.as_ptr());
    match GetProcAddress(module_handle, func_name) {
        Some(addr) => Ok(addr as usize),
        None => {
            let err = Error::from_win32();
            println!("Failed to find function '{}' in module: {:?}", target_function, module_handle);
            println!("Error details: {:?}", err);
            Err(err)
        }
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

// unsafe fn inline(process: &str, module: &str, function: &str){
//
//     let pid_result = get_pid(&process).unwrap();
//     let process_handle = get_process_handle(pid_result).unwrap();
//     let dirty_function_address = get_function_address(process_handle, &module, &function, pid_result).unwrap().unwrap();
//
//     let data = read_process_memory(process_handle, dirty_function_address, COMPARE_LENGTH);
//     print_prologue_bytes(data);
//
// }




fn hook_detected(){
    println!("Alert");
    println!("Hook detected");
    // MessageBoxA(
    //     0,
    //     CString::new("Hook detected").unwrap().as_ptr(),
    //     CString::new("Alert").unwrap().as_ptr(),
    //     0,
    // );
}

// Function to handle checking for detours in the functions array
unsafe fn detect_detour(module: &str, pid: u32, functions: &[&str]){
    // Get the base address of the specified running module
    let library_base = get_running_module_handle(module, pid).unwrap().unwrap();
    println!("Successfully loaded library: {}", module);

    // Check if the library base address is null
    if library_base.0 == ptr::null_mut() {
        eprintln!("Failed to load the module, error: {:?}", Error::from_win32());
        return;
    }

    // Parse DOS Header at the start of the module
    let dos_header: *const IMAGE_DOS_HEADER = library_base.0 as _;
    let nt_headers: *const IMAGE_NT_HEADERS64 = (library_base.0 as usize + (*dos_header).e_lfanew as usize) as _;
    println!("Successfully parsed DOS header and NT headers.");

    // Locate Export Directory
    let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress;
    let export_dir: *const IMAGE_EXPORT_DIRECTORY = (library_base.0 as usize + export_dir_rva as usize) as _;
    println!("Successfully located export directory.");

    // Access Export Table Arrays
    let address_of_functions =
        (library_base.0 as usize + (*export_dir).AddressOfFunctions as usize) as *const u32;
    let address_of_names =
        (library_base.0 as usize + (*export_dir).AddressOfNames as usize) as *const u32;
    let address_of_name_ordinals =
        (library_base.0 as usize + (*export_dir).AddressOfNameOrdinals as usize) as *const u16;
    println!("Successfully accessed export table arrays.");

    // Iterate through the exported names
    let num_names = (*export_dir).NumberOfNames;
    println!("Found {} exported functions.", num_names);

    for function_name in functions {
        // Access the function by name in the export directory
        let mut function_found = false;
        for i in 0..num_names {
            let name_rva = *address_of_names.offset(i as isize);
            let name_va = (library_base.0 as usize + name_rva as usize) as *const i8;
            let export_function_name = CStr::from_ptr(name_va).to_str().unwrap();

            if export_function_name == *function_name {
                function_found = true;
                let ordinal_index = *address_of_name_ordinals.offset(i as isize);
                let function_rva = *address_of_functions.offset(ordinal_index as isize);
                let function_address = (library_base.0 as usize + function_rva as usize) as *const u8;

                // Check syscall prologue
                let syscall_prologue: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];
                if std::slice::from_raw_parts(function_address, 4) != syscall_prologue {
                    // Check for JMP instruction
                    if *function_address == 0xE9 {
                        // Read the relative jump offset manually (4 bytes)
                        let relative_offset = *(function_address.offset(1) as *const u32) as isize;
                        let jump_target = function_address.offset(5).offset(relative_offset) as *const u8;

                        // Convert `module_name` into a mutable slice correctly
                        let mut module_name = vec![0u8; 512];
                        let module_name_slice = &mut module_name[..];
                        GetMappedFileNameA(
                            GetCurrentProcess(),
                            jump_target as _,
                            module_name_slice,
                        );
                        let module_name = CStr::from_ptr(module_name_slice.as_ptr() as _).to_string_lossy();

                        println!(
                            "Hooked: {} : {:?} into module {}",
                            export_function_name, function_address, module_name
                        );
                    } else {
                        println!("Potentially hooked: {} : {:?}", export_function_name, function_address);
                        println!("Checking function: {}", export_function_name);
                        println!("Function address: {:?}", function_address);
                        let function_bytes = std::slice::from_raw_parts(function_address, 4);
                        println!("First 4 bytes: {:?}", function_bytes);
                    }
                }
            }
        }

        if !function_found {
            println!("Function {} not found in the export directory.", function_name);
        }
    }
}

unsafe fn detect_inline_process_all(target_process: &str, target_module: &str, target_function: &str) -> Result<()> {

    let pid = get_pid(target_process)?;


    // 1. Get the base address of the module
    let module_handle = get_running_module_handle(target_module, pid).unwrap().unwrap();

    // 2. Parse the PE headers
    let dos_header: *const IMAGE_DOS_HEADER = module_handle.0 as _;
    let nt_headers: *const IMAGE_NT_HEADERS64 = (module_handle.0 as usize + (*dos_header).e_lfanew as usize) as _;

    // 3. Locate the section table and `.text` section
    //let mut section: *const IMAGE_SECTION_HEADER = ImageFirstSection(nt_headers);

    let section_table_start =
        (nt_headers as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;

    // Number of sections
    let num_sections = (*nt_headers).FileHeader.NumberOfSections as usize;

    let mut section = section_table_start;



    for _ in 0..(*nt_headers).FileHeader.NumberOfSections as usize {
        if section.is_null() {
            break;
        }

        let section_name = CStr::from_ptr((*section).Name.as_ptr() as *const i8)
            .to_str()
            .unwrap_or("");

        if section_name == ".text" {
            let text_start = module_handle.0.add((*section).VirtualAddress as usize);
            let text_size = (*section).SizeOfRawData as usize;

            println!("{:?} {}", text_start, text_size);
            break;
        }

        section = section.add(1);
    }




    // No hook detected
    println!("Failed to detect inline hook.");
    Ok(())
}

fn detect_inline_local(target_module: &str, target_function: &str) -> Result<Option<bool>> {

    // Common function prologues
    const MSVC_PROLOGUE: [u8; 2] = [0x8B, 0xFF]; // MOV EDI, EDI
    const GCC_PROLOGUE: [u8; 3] = [0x55, 0x48, 0x89]; // PUSH RBP, MOV RSP, RBP


    // Convert the module and function names to null-terminated C strings
    let module_name_c = CString::new(target_module).expect("CString::new failed");
    let module_name_pcstr: PCSTR = PCSTR(module_name_c.as_ptr() as *const u8);
    let function_name_c = CString::new(target_function).expect("CString::new failed");
    let function_name_pcstr: PCSTR = PCSTR(function_name_c.as_ptr() as *const u8);


    // Initialize result
    let mut function_preamble_hooked = false;

    unsafe {
        // Fetch the module handle
        println!("[~] Attempting to get module handle for {}", target_module);
        let h_mod: HMODULE = GetModuleHandleA(module_name_pcstr)?;
        if h_mod.is_invalid() {
            eprintln!("[!] Couldn't fetch module: {}", target_module);
            return Ok(Some(false));
        }
        println!("[✓] Module {} loaded at {:?}", target_module, h_mod);

        // Fetch the function address
        println!("[~] Looking up address for {}", target_function);
        let address_function = GetProcAddress(h_mod, function_name_pcstr);
        if address_function.is_none() {
            eprintln!("[!] Couldn't find address for function: {}", target_function);
            return Ok(Some(false));
        }
        println!("[✓] Function {} found at {:p}", target_function, address_function.unwrap());

        // Try to read the first byte of the function address
        let result = std::panic::catch_unwind(|| {
            let address = address_function.unwrap() as *const u8;
            

            println!("[~] Reading first byte at {:p}", address);

            let first_byte = unsafe { *address };
            println!("[+] First byte: 0x{:x}", first_byte);

            let is_hooked = matches!(first_byte, 0xE8 | 0xE9 | 0xEA | 0xEB);
            if is_hooked {
                println!("[!] Suspicious opcode detected: 0x{:x}", first_byte);
            } else {
                println!("[✓] Normal preamble byte detected: 0x{:x}", first_byte);
            }
            is_hooked
        });

        match result {
            Ok(is_hooked) => {
                function_preamble_hooked = is_hooked;
                println!("[~] Hook detection result: {}", is_hooked);
            },
            Err(_) => {
                eprintln!("Couldn't read bytes at function address: {}", target_function);
                eprintln!("[!] Memory access violation while reading {}", target_function);

                return Ok(Some(false));
            }
        }
    }
    println!("[+] Final detection result: {}", function_preamble_hooked);
    Ok(Some(function_preamble_hooked))
}


fn main() {

    unsafe {
        let pid = get_pid("msedge.exe").unwrap();
        //let functions = ["CopyFileW"];
        let function = "CopyFileW";

        //detect_detour("kernel32.dll", pid, &functions);

        let target_module = "kernel32.dll";

        detect_inline_local(target_module, function);
    }
}