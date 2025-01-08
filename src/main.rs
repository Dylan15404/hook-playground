use std::ffi::{c_void, CStr, CString};
use std::ptr;
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
use windows::Win32::System::LibraryLoader::LoadLibraryA;
use windows::Win32::System::ProcessStatus::GetMappedFileNameA;
use windows::Win32::System::Threading::GetCurrentProcess;


#[repr(C)]
#[derive(Debug)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: u32, // Offset to the NT headers
}

#[repr(C)]
#[derive(Debug)]
struct IMAGE_FILE_HEADER {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

#[repr(C)]
#[derive(Debug)]
struct IMAGE_OPTIONAL_HEADER {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    BaseOfData: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Debug)]
struct IMAGE_NT_HEADERS64 {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER,
}

#[repr(C)]
#[derive(Debug)]
struct IMAGE_EXPORT_DIRECTORY {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
}

#[repr(C)]
#[derive(Debug)]
struct IMAGE_DATA_DIRECTORY {
    VirtualAddress: u32,
    Size: u32,
}

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
        let module_handle = match get_running_module_handle(module_name, pid)? {
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

unsafe fn detect_inline_disk(module: &str){
    let library_base = get_static_module_handle(module).unwrap().unwrap();
    println!("Successfully loaded library: {}", module);

    if library_base.0 == ptr::null_mut() {
        eprintln!("Failed to load ntdll.dll, error: {:?}", Error::from_win32());
        return;
    }

    // Parse DOS Header
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

    for i in 0..num_names {
        let name_rva = *address_of_names.offset(i as isize);
        let name_va = (library_base.0 as usize + name_rva as usize) as *const i8;
        let function_name = CStr::from_ptr(name_va).to_str().unwrap();

        // Filter Nt|Zw functions
        if function_name.starts_with("Nt") || function_name.starts_with("Zw") {
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
                        function_name, function_address, module_name
                    );
                } else {
                    println!("Potentially hooked: {} : {:?}", function_name, function_address);
                }
            }
        }
    }
    println!("Detection complete.");
}

fn detect_inline_process(target_process: &str, target_module: &str, target_function: &str) -> Result<()> {

    let pid = get_pid(target_process)?;

    // Step 1: Open the process
    let process_handle = get_process_handle(pid)?;

    // Step 2: Get module handle and function address
    let module_handle = get_running_module_handle(target_module, pid)?.unwrap();


    let target_function_cstr = CString::new(target_function).unwrap();


    // Get the address of the target function from the loaded module
    let func_address = unsafe { GetProcAddress(module_handle, PCSTR(target_function_cstr.as_ptr() as *const u8)) };
    if func_address.is_none() {
        return Err(Error::from_win32());
    }

    // Step 3: Read memory of the target process
    const BUF_SIZE: usize = 512;
    let mut bytes: Vec<u8> = vec![0; BUF_SIZE];
    let mut bytes_read = 0;

    let read_result = unsafe { ReadProcessMemory(process_handle, func_address.unwrap() as *const c_void, bytes.as_mut_ptr() as _, BUF_SIZE, Some(&mut bytes_read)) };
    if read_result.is_err() {
        return Err(Error::from_win32());
    }

    // Step 4: Check the function bytes for possible hook patterns
    for i in 0..bytes.len() - 1 {
        if bytes[i] == 0x48 || bytes[i] == 0xFF {
            if bytes[i + 1] == 0xB8 || bytes[i + 1] == 0xE0 {
                // Potential hook detected
                hook_detected();
                return Ok(());
            }
        }
    }

    // No hook detected
    println!("Failed to detect inline hook.");
    Ok(())
}


fn main() {

    unsafe {
        //detect_inline_disk()
        detect_inline_process("msedge.exe", "kernel32.dll", "CopyFileW");
        //detect_inline_disk("kernel32.dll");
    }
}