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
