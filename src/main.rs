mod utils;
mod Modules;
mod Module;

use Modules::*;
use utils::{get_pid, get_process_handle, get_running_module_handle, get_static_module_handle};
use std::ffi::{c_void, CStr, CString, OsString};
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use std::ptr::{copy_nonoverlapping, null_mut};
use capstone::arch::{BuildsCapstone, BuildsCapstoneSyntax};
use capstone::{arch, Capstone, Insn};
use widestring::WideCString;
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
                GetModuleBaseNameW,
                GetProcessImageFileNameW
            },
            LibraryLoader::{
                LoadLibraryA
            },
            SystemServices::{
                IMAGE_EXPORT_DIRECTORY,
                IMAGE_DOS_HEADER
            },
            Memory::{
                MEMORY_BASIC_INFORMATION,
                VirtualQuery, 
                VirtualQueryEx, 
                MEM_IMAGE
            },

        },
        Foundation::{
            HMODULE,
            INVALID_HANDLE_VALUE,
            E_FAIL,
            CloseHandle,
            HANDLE,
            SetHandleInformation, 
            HANDLE_FLAG_PROTECT_FROM_CLOSE
        },
    }
};
use windows::Win32::Foundation::{GetLastError, BOOL};
use windows::Win32::System::Diagnostics::Debug::PSYMBOLSERVERGETINDEXSTRINGW;
use windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE32;
use windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS;

const COMPARE_LENGTH: usize = 20;
const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x00000002;
const LOAD_LIBRARY_AS_IMAGE_RESOURCE: u32 = 0x00000020;
const MAX_MODULE_NAME: usize = 256;

const X64_JUMP_PATTERN: [u8; 14] = [
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // JMP [rip+0x0]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // Absolute address
];

// Common function prologues
const MSVC_PROLOGUE: [u8; 2] = [0x8B, 0xFF]; // MOV EDI, EDI
const GCC_PROLOGUE: [u8; 3] = [0x55, 0x48, 0x89]; // PUSH RBP, MOV RSP, RBP

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

fn print_prologue_bytes(prologue: Vec<u8>, address: usize) {
    println!("Function Prologue (First {} Bytes):", prologue.len());
    for byte in &prologue {
        print!("{:02x} ", byte);
    }
    println!();
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(false)
        .build().unwrap();

    let insns = cs.disasm_all(&prologue, address as u64).unwrap();

    println!("Disassembled instructions:");
    for insn in insns.iter() {
        println!(
            "0x{:x}:\t{}\t{}",
            insn.address(),
            insn.mnemonic().unwrap_or(""),
            insn.op_str().unwrap_or("")
        );
    }

}

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
        let module_handle: HMODULE = GetModuleHandleA(module_name_pcstr)?;
        if module_handle.is_invalid() {
            eprintln!("[!] Couldn't fetch module: {}", target_module);
            return Ok(Some(false));
        }
        println!("[✓] Module {} loaded at {:?}", target_module, module_handle);

        // Fetch the function address
        println!("[~] Looking up address for {}", target_function);
        let address_function = GetProcAddress(module_handle, function_name_pcstr);
        if address_function.is_none() {
            eprintln!("[!] Couldn't find address for function: {}", target_function);
            return Ok(Some(false));
        }
        println!("[✓] Function {} found at {:p}", target_function, address_function.unwrap());



        // Try to read the first bytes of the function address
        let result = std::panic::catch_unwind(|| {
            let address = address_function.unwrap() as *const u8;
            println!("[~] Analyzing first 14 bytes at {:p}", address);

            let mut buffer: [u8; 14] = [0; 14];
            copy_nonoverlapping(address, buffer.as_mut_ptr(), buffer.len());

            // Check for x64 absolute jump (FF 25 00 00 00 00 followed by address)
            if buffer[0] == 0xFF && buffer[1] == 0x25 {
                println!("[!] Detected x64 absolute jump hook");
                return Ok::<bool, Error>(true);
            }

            // Check for short jumps (EB XX)
            if buffer[0] == 0xEB && buffer[1] != 0x00 {
                println!("[!] Detected short jump hook");
                return Ok::<bool, Error>(true);
            }

            // Check for common hooking library patterns
            if buffer.starts_with(&[0x60, 0xE8]) { // pushad + call
                println!("[!] Detected pushad+call hook pattern");
                return Ok::<bool, Error>(true);
            }

            if buffer.starts_with(&MSVC_PROLOGUE) || buffer.starts_with(&GCC_PROLOGUE) {
                println!("[✓] Valid function prologue detected");
                return Ok::<bool, Error>(false);
            }

            println!("[~] Reading first byte at {:p}", address);

            let first_byte = unsafe { *address };
            println!("[+] First byte: 0x{:x}", first_byte);

            let is_hooked = matches!(first_byte, 0xE8 | 0xE9 | 0xEA | 0xEB);
            if is_hooked {
                println!("[!] Suspicious opcode detected: 0x{:x}", first_byte);
            } else {
                println!("[✓] Normal preamble byte detected: 0x{:x}", first_byte);
            }
            Ok(is_hooked)
        });

        match result {
            Ok(is_hooked) => {
                function_preamble_hooked = is_hooked?;
                println!("[~] Hook detection result: {}", function_preamble_hooked);
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

fn get_function_bytes(target_module: &str, target_function: &str, num_bytes: usize) -> Result<(usize, Vec<u8>)> {
    // Convert the module and function names to null-terminated C strings.
    let module_name_c = CString::new(target_module).expect("CString::new failed");
    let module_name_pcstr = PCSTR(module_name_c.as_ptr() as *const u8);
    let function_name_c = CString::new(target_function).expect("CString::new failed");
    let function_name_pcstr = PCSTR(function_name_c.as_ptr() as *const u8);

    unsafe {
        // Fetch the module handle.
        let module_handle: HMODULE = GetModuleHandleA(module_name_pcstr)?;
        if module_handle.is_invalid() {
            return Err(Error::from_win32());
        }

        // Fetch the function address.
        let address_function = GetProcAddress(module_handle, function_name_pcstr);
        if address_function.is_none() {
            return Err(Error::from_win32());
        }

        let address = address_function.unwrap() as *const u8 as usize;

        // Allocate a buffer to hold the requested bytes.
        let mut buffer = vec![0u8; num_bytes];
        copy_nonoverlapping(address as *const u8, buffer.as_mut_ptr(), num_bytes);

        Ok((address, buffer))
    }
}


/*
fn get_process_modules(process_handle: HANDLE) -> Option<ProcessModules> {
    let mut memory_info = MEMORY_BASIC_INFORMATION::default();
    let mut module_list: Vec<MODULEINFO> = Vec::new();
    let mut last_module_path = String::new();

    unsafe {
        let mut current_address: *const c_void = std::ptr::null(); // Properly typed as *const c_void

        while VirtualQueryEx(
            process_handle,
            Option::from(current_address),
            &mut memory_info,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        ) != 0 {
            // Ensure the memory region is an image (executable code, DLLs, etc.)
            if memory_info.Type != MEM_IMAGE {
                current_address = (memory_info.BaseAddress as usize + memory_info.RegionSize) as *mut _;
                continue;
            }

            // Retrieve the module's full file path
            let mut file_path_buffer = vec![0u16; 260];
            let file_path_length = GetProcessImageFileNameW(
                process_handle,
                &mut *file_path_buffer,
            ) as usize;
            if file_path_length == 0 {
                current_address = (memory_info.BaseAddress as usize + memory_info.RegionSize) as *mut _;
                continue;
            }

            let mut file_path = WideCString::from_vec_truncate(&file_path_buffer[..file_path_length])
                .to_string_lossy();


            // If the same module spans multiple regions, merge the sizes
            if file_path == last_module_path {
                if let Some(last_module) = module_list.last_mut() {
                    *last_module.virtual_size() += memory_info.RegionSize;
                }
                current_address = (memory_info.BaseAddress as usize + memory_info.RegionSize) as *mut _;
                continue;
            }

            last_module_path = file_path.clone();

            let new_module = MODULEINFO::new(
                memory_info.BaseAddress,
                memory_info.RegionSize,
                file_path);

            module_list.push(new_module);

            current_address = (memory_info.BaseAddress as usize + memory_info.RegionSize) as *mut _;

        }

        if module_list.is_empty() {
            None
        } else {
            Some(ProcessModules { modules: module_list })
        }
    }
}*/

pub fn is_valid_process_handle(handle: HANDLE) -> bool {
    let mut exit_code: u32 = 0;
    unsafe {
        if GetExitCodeProcess(handle, &mut exit_code).is_err() {
            return false; // The function failed, meaning the handle is likely invalid.
        }
    }
    true // The function succeeded, meaning the handle is valid.
}




unsafe fn get_modules(pid: u32) -> Result<Vec<Vec<u8>>> {
    let process_handle = get_process_handle(pid)?;
    println!("handle valid: {}", is_valid_process_handle(process_handle));

    // Create a snapshot of the modules in the process
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)?;
    println!("Creating snapshot for PID: {}", pid);
    println!("Snapshot handle: {:?}", snapshot);

    // Initialize the module entry structure
    let mut modules = Vec::new();
    let mut entry = MODULEENTRY32 {
        dwSize: size_of::<MODULEENTRY32>() as u32,
        ..Default::default()
    };
    println!("Module entry size: {}", size_of::<MODULEENTRY32>());

    Module32First(snapshot, &mut entry) ?;

    loop {
        // Capture module data
        let base_address = entry.modBaseAddr;
        let module_size = entry.modBaseSize as usize;
        let path = entry.szExePath;


        // Allocate buffer for module data
        let mut buffer = vec![0u8; module_size];
        let mut bytes_read = 0;

        // Read process memory
        let result =
            ReadProcessMemory(
                process_handle,
                base_address as _,
                buffer.as_mut_ptr() as _,
                module_size,
                Some(&mut bytes_read)
            );
        println!("bytes_read: {}", bytes_read);
        if result.is_ok() {
            buffer.truncate(bytes_read); // Adjust buffer to bytes actually read
            modules.push(buffer);
        } else {
            let err = unsafe { GetLastError() };
            eprintln!("Failed to read module at {base_address:p}: {}", Error::from(err));
        }
        // Move to next module
        match unsafe { Module32Next(snapshot, &mut entry) } {
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    if let Err(e) = CloseHandle(snapshot) {
        eprintln!("Failed to close snapshot handle: {}", e);
    }
    if let Err(e) = CloseHandle(process_handle) {
        eprintln!("Failed to close process handle: {}", e);
    }
    println!("Loaded {} modules from memory", modules.len());
    Ok(modules)

}



fn attempt(buffer: Vec<u8>) {
    use goblin::pe::PE;
    use std::fs::File;
    use std::io::Read;


        match PE::parse(&buffer) {
            Ok(pe) => {
                println!("PE file parsed successfully");

                // Inspect the Export Address Table (EAT)
                for export in pe.exports {
                    println!(
                        "Function: {}, Address: {:x}",
                        export.name.unwrap_or("unknown"),
                        export.rva
                    );
                }

                // Inspect the Import Address Table (IAT)
                for import in pe.imports {
                    println!("Import: {}, Address: {:x}", import.name, import.rva);
                }
            },
            Err(e) => println!("Failed to parse PE file: {}", e),
        }
}
fn main() {

    unsafe {
        let pid = get_pid("msedge.exe").unwrap();

        //let header = get_modules(pid).expect("get_modules failed");
        //attempt(header);
        let mut modules = Modules::modules::new();
        modules.load_modules(pid);

/*

        let pid = get_pid("msedge.exe").unwrap();
        let process_handle = get_process_handle(pid).unwrap();


        //let functions = ["CopyFileW"];
        let function = "CreateToolhelp32Snapshot";

        //detect_detour("kernel32.dll", pid, &functions);

        let target_module = "kernel32.dll";

        //detect_inline_local(target_module, function);

        let modules = get_process_modules(process_handle).unwrap();

        assert!(!modules.modules.is_empty(), "Module list is empty");
        for module in modules.modules.iter() {
            println!("Module: {} at {:?}", module.path_file(), module.virtual_base());
            assert!(!module.path_file().is_empty(), "Module file path is empty");
        }

        // let out = get_function_bytes(target_module, function, 300).unwrap();
        // let address = out.0;
        // let bytes = out.1;
        // print_prologue_bytes(bytes, address);
*/
    }
}