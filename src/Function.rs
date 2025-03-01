pub struct function {

    pub valid: Option<bool>,

    pub name: String,

    pub clean_data: Option<Vec<u8>>,

    pub dirty_data: Option<Vec<u8>>,

    pub start_index: Option<usize>,

    pub end_index: Option<usize>,


}

impl function {

    pub fn new(name: String,  dirty_data: Option<Vec<u8>>, start_index: Option<usize>, end_index: Option<usize>) -> Self {
        Self {
            valid: None,
            name,
            clean_data: None,
            dirty_data,
            start_index,
            end_index,
        }
    }
}
