use object::SectionIndex;
use crate::ecu::EcuDescription;

pub struct SymInfo {
    pub name: String,
    pub address: u64,
    pub section_index: Option<SectionIndex>,
    pub is_section_sym: bool,
}

pub fn process_section(
    _section_data: &[u8],
    _section_index: SectionIndex,
    _symbols: &[SymInfo],
    _ecu: &EcuDescription,
    _ori_buf: &[u8],
) {
    // TODO: implement in Task 9
}
