use windows::{core::*, Win32::System};
use windows::Win32::System::LibraryLoader::{LoadLibraryExA, GetModuleHandleA, GetProcAddress, LOAD_LIBRARY_FLAGS};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use std::ptr::{null, null_mut};
use windows::core::{PCWSTR, HSTRING};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::Foundation::FARPROC;
use std::slice;

const COMPARE_LENGTH: usize = 14;

fn get_clean_fn(mod_name : &str, fn_name: &str) -> FARPROC{
    //convert input strings to PCSTR
    let pcstr_mod_name = PCSTR::from_raw(mod_name.as_ptr());
    let pcstr_fn_name = PCSTR::from_raw(fn_name.as_ptr());

    //Get the Address of the function from the library in disk
    let h_module = unsafe { GetModuleHandleA(pcstr_mod_name) }
        .expect("Failed to get module handle");

    //Get the Address of the function from the library
    let target_func = unsafe { GetProcAddress(h_module, pcstr_fn_name) };

    target_func
}

fn get_dirty_fn(mod_name : &str, fn_name: &str) -> FARPROC{
    //convert input strings to PCSTR
    let pcstr_mod_name = PCSTR::from_raw(mod_name.as_ptr());
    let pcstr_fn_name = PCSTR::from_raw(fn_name.as_ptr());

    // add LOAD_LIBRARY_AS_IMAGE_RESOURCE flag
    let flags = LOAD_LIBRARY_FLAGS(0x00000020);

    //Load Library as module with relevant flags
    let h_module = unsafe { LoadLibraryExA(pcstr_mod_name, *null(), flags) }
        .expect("Failed to load library from memory");

    //Get the Address of the function from the library in memory
    let target_func = unsafe { GetProcAddress(h_module, pcstr_fn_name) };

    target_func
}

fn obtain_prologue(fn_clean: &FARPROC, fn_dirty: &FARPROC, function_name: &str) -> bool {
    unsafe {
        // Compare the first COMPARE_LENGTH bytes at both pointers
        let clean_slice = slice::from_raw_parts(fn_clean, COMPARE_LENGTH);
        let dirty_slice = slice::from_raw_parts(fn_dirty, COMPARE_LENGTH);

        if clean_slice != dirty_slice {
            // Log the detection of an inline hook
            println!("Inline hook detected in {}!", function_name);
            return true;
        }
    }
    false
}

fn main() {
    // Define the module and function name for testing
    let mod_name = "user32.dll";
    let fn_name = "MessageBoxA";

    // Obtain the function pointers (clean and dirty versions)
    let fn_clean = get_clean_fn(mod_name, fn_name);
    let fn_dirty = get_dirty_fn(mod_name, fn_name);

    // Check for inline hooking
    let function_name = fn_name;
    if obtain_prologue(&fn_clean, &fn_dirty, function_name) {
        println!("Inline hook detected in {}!", function_name);
    } else {
        println!("No inline hook detected in {}.", function_name);
    }
}