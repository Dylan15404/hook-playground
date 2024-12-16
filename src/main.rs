use windows::{core::*, Win32::System::LibraryLoader::{LoadLibraryExA, GetModuleHandleA, GetProcAddress, LOAD_LIBRARY_FLAGS}};
use std::slice;
use windows::Win32::Foundation::{HMODULE};

const COMPARE_LENGTH: usize = 14;
const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x00000002;
const LOAD_LIBRARY_AS_IMAGE_RESOURCE: u32 = 0x00000020;

fn get_clean_fn(mod_name : &str, fn_name: &str) -> unsafe extern "system" fn() -> isize {
    //convert input strings to PCSTR
    let pcstr_mod_name = PCSTR::from_raw(mod_name.as_ptr());
    let pcstr_fn_name = PCSTR::from_raw(fn_name.as_ptr());

    //Get the Address of the function from the library in disk
    let h_module = unsafe { GetModuleHandleA(pcstr_mod_name) }
        .expect("Failed to get module handle");

    //Get the Address of the function from the library
    let target_func = unsafe { GetProcAddress(h_module, pcstr_fn_name) }
        .expect("Failed to get function address");

    target_func
}

fn read_prologue_from_process(pid: u32, function_address: usize, size: usize) -> Option<Vec<u8>> {
    let process_handle = unsafe { OpenProcess(PROCESS_VM_READ, 0, pid) };
    if process_handle.is_null() {
        return None;
    }

    let mut buffer = vec![0; size];
    let mut bytes_read = 0;
    let result = unsafe {
        ReadProcessMemory(
            process_handle,
            function_address as *const _,
            buffer.as_mut_ptr() as *mut _,
            size,
            &mut bytes_read,
        )
    };

    if result != 0 {
        Some(buffer)
    } else {
        None
    }
}

fn compare_prologues(fn_clean: &unsafe extern "system" fn() -> isize, fn_dirty: &unsafe extern "system" fn() -> isize, function_name: &str) -> bool {
    unsafe {
        let clean_slice = slice::from_raw_parts(*fn_clean as *const u8, COMPARE_LENGTH);
        let dirty_slice = slice::from_raw_parts(*fn_dirty as *const u8, COMPARE_LENGTH);

        if clean_slice != dirty_slice {
            println!("Inline hook detected in {}!", function_name);
            return true;
        }
    }
    false
}

fn detect_inline(mod_name : &str, fn_name: &str) -> (){

    let target_process_id: u32 = 1234; // Example process ID

    //convert input strings to PCSTR
    let pcstr_mod_name = PCSTR::from_raw(mod_name.as_ptr());
    let pcstr_fn_name = PCSTR::from_raw(fn_name.as_ptr());

    //set flags for library loading
    let flags = LOAD_LIBRARY_FLAGS(LOAD_LIBRARY_AS_IMAGE_RESOURCE);

    //Load Library as module with relevant flags
    let h_module = unsafe { LoadLibraryExA(pcstr_mod_name, None, flags) }
        .expect("Failed to load library from memory");

    let dirty_fn = get_dirty_fn(h_module, pcstr_fn_name);
    let clean_fn = get_clean_fn(h_module, pcstr_fn_name);
}

fn main() {
    let mod_name = "user32.dll";
    let fn_name = "MessageBoxA";

    let fn_clean = get_clean_fn(mod_name, fn_name);
    let fn_dirty = get_dirty_fn(mod_name, fn_name);

    if compare_prologues(&fn_clean, &fn_dirty, fn_name) {
        println!("Hook detected!");
    } else {
        println!("No hook detected.");
    }
}