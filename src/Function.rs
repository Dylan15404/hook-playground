pub struct function {

    pub name: String,
    pub export_module: String,
    pub va: u64,
    pub rva: u64,


    pub clean_data: Option<Vec<u8>>,

    pub dirty_data: Option<Vec<u8>>,

    pub start_index: Option<usize>,

    pub end_index: Option<usize>,

    pub valid: Option<bool>,


}

impl function {

    pub fn new(name: String, export_module: String, va: u64, rva: u64,) -> Self {
        Self {
            name,
            export_module,
            va,
            rva,
            valid: None,
            clean_data: None,
            dirty_data: None,
            start_index: None,
            end_index: None,

        }
    }
}
