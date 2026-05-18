// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aleksei Markelov

pub struct EcuDescription {
    pub name: &'static str,
    pub patch_method_prefix: &'static str,
    pub short_pointer_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_ecu_sh2() {
        let e = find_ecu("mmc-sh2").unwrap();
        assert_eq!(e.name, "mmc-sh2");
        assert_eq!(e.patch_method_prefix, "[sh-");
        assert_eq!(e.short_pointer_size, 4);
    }

    #[test]
    fn test_find_ecu_m32r() {
        let e = find_ecu("mmc-m32r").unwrap();
        assert_eq!(e.name, "mmc-m32r");
        assert_eq!(e.patch_method_prefix, "[m32r-");
        assert_eq!(e.short_pointer_size, 2);
    }

    #[test]
    fn test_find_ecu_unknown() {
        assert!(find_ecu("unknown").is_none());
    }
}

static SUPPORTED_ECUS: &[EcuDescription] = &[
    EcuDescription {
        name: "mmc-sh2",
        patch_method_prefix: "[sh-",
        short_pointer_size: 4,
    },
    EcuDescription {
        name: "mmc-m32r",
        patch_method_prefix: "[m32r-",
        short_pointer_size: 2,
    },
];

pub fn find_ecu(name: &str) -> Option<&'static EcuDescription> {
    SUPPORTED_ECUS.iter().find(|e| e.name == name)
}
