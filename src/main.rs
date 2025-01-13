use std::ffi::{c_void, CStr, CString};
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
                Module32Next
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
                IMAGE_SECTION_HEADER
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
                GetMappedFileNameA
            },
            LibraryLoader::{
                LoadLibraryA
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
fn get_function_address(process_handle: HANDLE, module_name: &str, function_name: &str, pid: u32) -> Result<Option<*mut u8>> {
    unsafe {
        // STEP 1: GET FUNCTION OFFSET

        // Unwrap the module handle from the result
        let module_handle = match get_running_module_handle(module_name, pid)? {
            Some(handle) => handle,
            None => {
                eprintln!("Failed to get module handle for {}", module_name);
                return Err(Error::from_win32());
            }
        };

        // Get the export directory of the module
        let dos_header: *const IMAGE_DOS_HEADER = module_handle.0 as _;
        if dos_header.is_null() {
            eprintln!("Invalid DOS header");
            return Err(Error::from_win32());
        }

        let nt_headers = ((module_handle.0 as usize) + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if nt_headers.is_null() {
            eprintln!("Invalid NT headers");
            return Err(Error::from_win32());
        }

        let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress;
        if export_dir_rva == 0 {
            eprintln!("No export directory found");
            return Err(Error::from_win32());
        }

        // Calculate the virtual address of the export directory
        let export_dir_va = (module_handle.0 as usize + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

        if export_dir_va.is_null() {
            eprintln!("Failed to calculate export directory address");
            return Err(Error::from_win32());
        }

        // Validate the AddressOfNames and NumberOfNames fields
        let name_rva_ptr = (*export_dir_va).AddressOfNames as *const u32;
        let number_of_names = (*export_dir_va).NumberOfNames;

        if name_rva_ptr.is_null() || number_of_names == 0 {
            eprintln!("No function names found");
            return Err(Error::from_win32());
        }

        // Ensure that the index `i` is within bounds
        for i in 0..number_of_names as usize {
            // Check if `name_rva_ptr` is valid and within bounds
            let name_rva = if let Some(valid_name_rva) = name_rva_ptr.add(i).as_ref() {
                *valid_name_rva
            } else {
                eprintln!("Out of bounds access: name_rva_ptr.add({}) is invalid", i);
                continue;  // Skip this iteration
            };

            // Validate the RVA before proceeding
            if name_rva == 0 {
                continue;
            }

            // Calculate the virtual address of the function name string
            let name_va = (module_handle.0 as usize + name_rva as usize) as *const i8;

            if name_va.is_null() {
                continue;
            }

            // Safely read the name string
            let name = match CStr::from_ptr(name_va).to_str() {
                Ok(n) => n,
                Err(_) => continue,
            };

            if name == function_name {
                // Get the function's RVA (Relative Virtual Address)
                let func_index = *((*export_dir_va).AddressOfNameOrdinals as *const u16).add(i) as usize;
                let function_rva = *((*export_dir_va).AddressOfFunctions as *const u32).add(func_index);

                if function_rva == 0 {
                    eprintln!("Function RVA is zero");
                    return Err(Error::from_win32());
                }

                // Calculate the function's virtual address
                let function_va = (module_handle.0 as usize + function_rva as usize) as *mut u8;

                return Ok(Some(function_va));
            }
        }
    }

    // If no matching function name is found
    eprintln!("Function {} not found in module {}", function_name, module_name);
    Err(Error::from_win32())
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
    // Get the base address of the specified module using a static handle
    let library_base = get_static_module_handle(module).unwrap().unwrap();
    println!("Successfully loaded library: {}", module);

    // Check if the library base address is null
    if library_base.0 == ptr::null_mut() {
        eprintln!("Failed to load ntdll.dll, error: {:?}", Error::from_win32());
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

// extern "C" {
//     fn ImageFirstSection(nt_header: *const IMAGE_NT_HEADERS64) -> *const IMAGE_SECTION_HEADER;
// }

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

unsafe fn detect_inline_process(target_process: &str, target_module: &str, target_function: &str) -> Result<()> {

    let pid = get_pid(target_process)?;

    // 2. Open a handle to the target process
    let process_handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        false,
        pid,
    )?;
    if process_handle.is_invalid() {
        return Err(Error::from_win32());
    }

    // Ensure the handle is closed properly
    //defer!(CloseHandle(process_handle));

    // 1. Get the base address of the module
    let module_handle = get_running_module_handle(target_module, pid).unwrap().unwrap();

    // 4. Resolve the address of the target function
    let func_address = get_function_address(process_handle, target_module, target_function, pid)?.unwrap();

    // 2. Parse the PE headers
    let dos_header: *const IMAGE_DOS_HEADER = module_handle.0 as _;
    let nt_headers: *const IMAGE_NT_HEADERS64 = (module_handle.0 as usize + (*dos_header).e_lfanew as usize) as _;



    // 6. Locate the `.text` section
    //let mut section: *const IMAGE_SECTION_HEADER = ImageFirstSection(nt_headers);

    let section_table_start =
        (nt_headers as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;

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

            // 7. Check if the function address is within the `.text` section
            if func_address as usize >= text_start as usize
                && ((func_address as usize) < (text_start as usize + text_size))
            {
                // Calculate offset within `.text` and read contents
                let func_offset = func_address as usize - text_start as usize;
                let func_bytes = std::slice::from_raw_parts(
                    text_start.add(func_offset) as *const u8,
                    text_size - func_offset,
                );

                println!("Function bytes: {:x?}", &func_bytes[..std::cmp::min(32, func_bytes.len())]);
            } else {
                println!("Function is outside the .text section");
            }
            break;
        }

        section = section.add(1);
    }

    Ok(())
}


fn main() {

    // println!("cargo:rustc-link-lib=imagehlp");
    // println!("cargo:rustc-link-lib=dbghelp");
    // println!("cargo:rustc-link-search=native=C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.26100.0\\um\\x64\\ImageHlp.Lib");

    unsafe {
        //detect_inline_disk()
        detect_inline_process("msedge.exe", "kernel32.dll", "CopyFileW").expect("TODO: panic message");
        //detect_inline_disk("kernel32.dll");
    }
}