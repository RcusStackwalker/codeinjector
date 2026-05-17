use object::SectionIndex;
use crate::ecu::EcuDescription;

pub struct SymInfo {
    pub name: String,
    pub address: u64,
    pub section_index: Option<SectionIndex>,
    pub is_section_sym: bool,
}

fn get_symbol<'a>(name: &str, symbols: &'a [SymInfo]) -> Option<&'a SymInfo> {
    symbols.iter().find(|s| s.name == name)
}

fn get_data_symbol<'a>(desc_sym_name: &str, symbols: &'a [SymInfo]) -> Option<&'a SymInfo> {
    if desc_sym_name.len() < 3 {
        return None;
    }
    get_symbol(&desc_sym_name[2..], symbols)
}

fn get_data_desc_string(sym_address: u64, section_data: &[u8]) -> Option<String> {
    let offset = sym_address as usize;
    let data = section_data.get(offset..)?;
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    Some(String::from_utf8_lossy(&data[..end]).into_owned())
}

#[derive(PartialEq)]
enum DataDescType {
    Unknown,
    Value,
    Array,
    Array3D,
    Map2D8,
    Map3D8,
    Map2D16,
    Map3D16,
    Axis,
    AxisEx,
}

fn get_data_desc_type(s: &str) -> DataDescType {
    match s.splitn(2, ';').next().unwrap_or("") {
        "value"   => DataDescType::Value,
        "array"   => DataDescType::Array,
        "3darray" => DataDescType::Array3D,
        "2dmap8"  => DataDescType::Map2D8,
        "3dmap8"  => DataDescType::Map3D8,
        "2dmap16" => DataDescType::Map2D16,
        "3dmap16" => DataDescType::Map3D16,
        "axis"    => DataDescType::Axis,
        "axisex"  => DataDescType::AxisEx,
        _         => DataDescType::Unknown,
    }
}

fn get_axis_size(rom_addr: usize, ori_buf: &[u8], short_pointer_size: usize) -> u16 {
    let offset = rom_addr + 2 * short_pointer_size;
    if offset + 2 > ori_buf.len() {
        return 0;
    }
    u16::from_be_bytes(ori_buf[offset..offset + 2].try_into().unwrap_or([0, 0]))
}

fn emit_value_data_desc(s: &str, data_addr: u64) {
    let mut p = s.splitn(5, ';');
    let _ty  = p.next().unwrap_or("");
    let cat  = p.next().unwrap_or("");
    let name = p.next().unwrap_or("");
    let scl  = p.next().unwrap_or("");
    println!("<table name=\"{}\" category=\"{}\" address=\"{:x}\" type=\"1D\" scaling=\"{}\"/>",
        name, cat, data_addr as u32, scl);
}

fn emit_array_data_desc(s: &str, data_addr: u64) {
    let mut p = s.splitn(6, ';');
    let _ty   = p.next().unwrap_or("");
    let cat   = p.next().unwrap_or("");
    let name  = p.next().unwrap_or("");
    let scl   = p.next().unwrap_or("");
    let axdsc = p.next().unwrap_or("");
    println!("<table name=\"{}\" category=\"{}\" address=\"{:x}\" type=\"2D\" scaling=\"{}\">\n\t{}\n</table>\n",
        name, cat, data_addr as u32, scl, axdsc);
}

fn emit_3darray_data_desc(s: &str, data_addr: u64) {
    let mut p = s.splitn(7, ';');
    let _ty  = p.next().unwrap_or("");
    let cat  = p.next().unwrap_or("");
    let name = p.next().unwrap_or("");
    let scl  = p.next().unwrap_or("");
    let xdsc = p.next().unwrap_or("");
    let ydsc = p.next().unwrap_or("");
    println!("<table name=\"{}\" category=\"{}\" address=\"{:x}\" type=\"3D\" scaling=\"{}\">\n\t{}\n\t{}\n</table>\n",
        name, cat, data_addr as u32, scl, xdsc, ydsc);
}

fn emit_axis_ex_desc(
    axis_sym_name: &str,
    axis_type: &str,
    symbols: &[SymInfo],
    section_data: &[u8],
    ori_buf: &[u8],
    short_pointer_size: usize,
) {
    let desc_sym = get_symbol(axis_sym_name, symbols);
    let data_sym = desc_sym.and_then(|s| get_data_symbol(&s.name, symbols));

    match (desc_sym, data_sym) {
        (Some(ds), Some(da)) => {
            if let Some(str_val) = get_data_desc_string(ds.address, section_data) {
                let mut p = str_val.splitn(4, ';');
                let _ty  = p.next().unwrap_or("");
                let name = p.next().unwrap_or("");
                let scl  = p.next().unwrap_or("");
                let axis_size = get_axis_size(da.address as usize, ori_buf, short_pointer_size);
                let axis_header = 2 * short_pointer_size + 2;
                println!(
                    "\t<table name=\"{}\" type=\"{} Axis\" address=\"{:x}\" elements=\"{}\" scaling=\"{}\"/>",
                    name, axis_type, da.address as usize + axis_header, axis_size, scl
                );
            }
        }
        _ => {
            println!("\t<table name=\"{}\" type=\"{} Axis\"/>", axis_sym_name, axis_type);
        }
    }
}

fn emit_axis_desc(
    axis_sym_name: &str,
    axis_type: &str,
    symbols: &[SymInfo],
    section_data: &[u8],
    ori_buf: &[u8],
    short_pointer_size: usize,
) {
    if axis_sym_name.as_bytes().get(1) == Some(&b'X') {
        emit_axis_ex_desc(axis_sym_name, axis_type, symbols, section_data, ori_buf, short_pointer_size);
        return;
    }

    let desc_sym = get_symbol(axis_sym_name, symbols);
    let data_sym = desc_sym.and_then(|s| get_data_symbol(&s.name, symbols));

    match (desc_sym, data_sym) {
        (Some(ds), Some(da)) => {
            if let Some(str_val) = get_data_desc_string(ds.address, section_data) {
                let mut p = str_val.splitn(5, ';');
                let _ty   = p.next().unwrap_or("");
                let name  = p.next().unwrap_or("");
                let scl   = p.next().unwrap_or("");
                let size  = p.next().unwrap_or("");
                let axis_header = 2 * short_pointer_size + 2;
                println!(
                    "\t<table name=\"{}\" type=\"{} Axis\" address=\"{:x}\" elements=\"{}\" scaling=\"{}\"/>",
                    name, axis_type, da.address as usize + axis_header, size, scl
                );
            }
        }
        _ => {
            println!("\t<table name=\"{}\" type=\"{} Axis\"/>", axis_sym_name, axis_type);
        }
    }
}

fn emit_2dmap_data_desc(
    s: &str,
    data_addr: u64,
    symbols: &[SymInfo],
    section_data: &[u8],
    ori_buf: &[u8],
    short_pointer_size: usize,
) {
    let mut p = s.splitn(6, ';');
    let _ty      = p.next().unwrap_or("");
    let cat      = p.next().unwrap_or("");
    let name     = p.next().unwrap_or("");
    let scl      = p.next().unwrap_or("");
    let axisname = p.next().unwrap_or("").to_string();
    println!("<table name=\"{}\" category=\"{}\" address=\"{:x}\" type=\"2D\" scaling=\"{}\">",
        name, cat, data_addr as u32, scl);
    emit_axis_desc(&axisname, "Y", symbols, section_data, ori_buf, short_pointer_size);
    println!("</table>\n");
}

fn emit_3dmap_data_desc(
    s: &str,
    data_addr: u64,
    symbols: &[SymInfo],
    section_data: &[u8],
    ori_buf: &[u8],
    short_pointer_size: usize,
) {
    let mut p = s.splitn(7, ';');
    let _ty       = p.next().unwrap_or("");
    let cat       = p.next().unwrap_or("");
    let name      = p.next().unwrap_or("");
    let scl       = p.next().unwrap_or("");
    let xaxisname = p.next().unwrap_or("").to_string();
    let yaxisname = p.next().unwrap_or("").to_string();
    println!("<table name=\"{}\" category=\"{}\" address=\"{:x}\" type=\"3D\" scaling=\"{}\" swapxy=\"true\">",
        name, cat, data_addr as u32, scl);
    emit_axis_desc(&xaxisname, "X", symbols, section_data, ori_buf, short_pointer_size);
    emit_axis_desc(&yaxisname, "Y", symbols, section_data, ori_buf, short_pointer_size);
    println!("</table>\n");
}

pub fn process_section(
    section_data: &[u8],
    section_index: SectionIndex,
    symbols: &[SymInfo],
    ecu: &EcuDescription,
    ori_buf: &[u8],
) {
    let ptr = ecu.short_pointer_size;

    for sym in symbols.iter().filter(|s| {
        s.section_index == Some(section_index) && !s.is_section_sym
    }) {
        let desc_str = match get_data_desc_string(sym.address, section_data) {
            Some(s) if !s.is_empty() => s,
            _ => {
                println!("<comment>That's strange: unable to find desc string for {}</comment>", sym.name);
                continue;
            }
        };
        let data_sym = match get_data_symbol(&sym.name, symbols) {
            Some(s) => s,
            None => {
                println!("<comment>That's strange: unable to find data symbol for {}</comment>", sym.name);
                continue;
            }
        };
        let da = data_sym.address;

        match get_data_desc_type(&desc_str) {
            DataDescType::Value   => emit_value_data_desc(&desc_str, da),
            DataDescType::Array   => emit_array_data_desc(&desc_str, da),
            DataDescType::Array3D => emit_3darray_data_desc(&desc_str, da),
            DataDescType::Map3D8  => emit_3dmap_data_desc(&desc_str, da + (3 + 2*ptr) as u64, symbols, section_data, ori_buf, ptr),
            DataDescType::Map3D16 => emit_3dmap_data_desc(&desc_str, da + (6 + 2*ptr) as u64, symbols, section_data, ori_buf, ptr),
            DataDescType::Map2D8  => emit_2dmap_data_desc(&desc_str, da + (2 + ptr) as u64,   symbols, section_data, ori_buf, ptr),
            DataDescType::Map2D16 => emit_2dmap_data_desc(&desc_str, da + (4 + ptr) as u64,   symbols, section_data, ori_buf, ptr),
            DataDescType::Axis | DataDescType::AxisEx => { /* skipped explicitly */ }
            DataDescType::Unknown => println!("<comment name=\"{}\">{}</comment>", sym.name, desc_str),
        }
    }
}
