#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PatchMethod {
    M32rBl,
    M32rLd24R0,
    M32rLd24R4,
    M32rLduhR1,
    M32rSpliceIntoFunction,
    M32rRelocateSection,
    ShJumpToBody,
    ShSpliceIntoFunction,
    ShRelocateSection,
    Generic,
}

static PATCH_MARKERS: &[(&str, PatchMethod)] = &[
    ("[m32r-bl]",                     PatchMethod::M32rBl),
    ("[m32r-ld24-r0]",                PatchMethod::M32rLd24R0),
    ("[m32r-ld24-r4]",                PatchMethod::M32rLd24R4),
    ("[m32r-lduh-r1]",                PatchMethod::M32rLduhR1),
    ("[m32r-splice-into-function]",   PatchMethod::M32rSpliceIntoFunction),
    ("[m32r-relocate-section]",       PatchMethod::M32rRelocateSection),
    ("[sh-jump-to-body]",             PatchMethod::ShJumpToBody),
    ("[sh-splice-into-function]",     PatchMethod::ShSpliceIntoFunction),
    ("[sh-relocate-section]",         PatchMethod::ShRelocateSection),
];

pub fn get_patch_method(name: &str) -> PatchMethod {
    for (marker, method) in PATCH_MARKERS {
        if name.contains(marker) {
            return *method;
        }
    }
    PatchMethod::Generic
}

use crate::ecu::EcuDescription;

fn hex_print(data: &[u8]) {
    for b in data {
        print!("{:02x}", b);
    }
}

fn print_patch_xml(
    section_name: &str,
    patch_address: usize,
    patch_size: usize,
    ori_buf: &[u8],
    out_buf: &[u8],
) {
    let scaling_name = format!("{} _scaling", section_name).replace('.', "_");
    println!("<scaling name=\"{}\" storagetype=\"bloblist\">", scaling_name);
    print!("\t<data name=\"Original\" value=\"");
    hex_print(&ori_buf[patch_address..patch_address + patch_size]);
    println!("\" />");
    print!("\t<data name=\"Patched\" value=\"");
    hex_print(&out_buf[patch_address..patch_address + patch_size]);
    println!("\" />\n</scaling>\n");
    println!(
        "<table name=\"{}\" address=\"{:x}\" category=\"Patches\" type=\"1D\" scaling=\"{}\" />\n",
        section_name, patch_address, scaling_name
    );
}

pub fn inject_section(
    name: &str,
    vma: usize,
    section_data: &[u8],
    ecu: &EcuDescription,
    ori_buf: &[u8],
    out_buf: &mut Vec<u8>,
) {
    let method = get_patch_method(name);

    if method != PatchMethod::Generic {
        if !name.contains(ecu.patch_method_prefix) {
            println!("patch_method incompatible with arch at {}", name);
            crate::usage_and_exit();
        }
    }

    let sec_size = section_data.len();
    let (patch_address, patch_size): (usize, usize) = match method {
        PatchMethod::Generic => {
            out_buf[vma..vma + sec_size].copy_from_slice(section_data);
            (vma, sec_size)
        }
        _ => return, // TODO: Tasks 6-8
    };

    print_patch_xml(name, patch_address, patch_size, ori_buf, out_buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_patch_method_all_markers() {
        assert_eq!(get_patch_method("[m32r-bl].text"),                    PatchMethod::M32rBl);
        assert_eq!(get_patch_method("[m32r-ld24-r0].text"),               PatchMethod::M32rLd24R0);
        assert_eq!(get_patch_method("[m32r-ld24-r4].text"),               PatchMethod::M32rLd24R4);
        assert_eq!(get_patch_method("[m32r-lduh-r1].text"),               PatchMethod::M32rLduhR1);
        assert_eq!(get_patch_method("[m32r-splice-into-function].text"),  PatchMethod::M32rSpliceIntoFunction);
        assert_eq!(get_patch_method("[m32r-relocate-section].text"),      PatchMethod::M32rRelocateSection);
        assert_eq!(get_patch_method("[sh-jump-to-body].text"),            PatchMethod::ShJumpToBody);
        assert_eq!(get_patch_method("[sh-splice-into-function].text"),    PatchMethod::ShSpliceIntoFunction);
        assert_eq!(get_patch_method("[sh-relocate-section].text"),        PatchMethod::ShRelocateSection);
        assert_eq!(get_patch_method("generic_section"),                   PatchMethod::Generic);
        assert_eq!(get_patch_method("data_desc"),                        PatchMethod::Generic);
    }
}
