use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    mem::MaybeUninit,
    os::unix::{ffi::OsStrExt as _, fs::PermissionsExt},
    path::{Path, PathBuf},
};

mod notes;
mod vm;

use anyhow::Result;
use object::{
    read::elf::{Dyn as _, ElfFile, FileHeader, ProgramHeader},
    Object,
};
use vm::Pod as _;

trait BitWidth: Copy + Clone {
    /// SAFETY: the slice must be at least `Self::BYTES` long.
    unsafe fn from_bytes(bytes: &[u8], endian: impl object::Endian) -> Self;
    /// SAFETY: the slice must be at least `Self::BYTES` long.
    unsafe fn to_bytes(&self, endian: impl object::Endian, bytes: &mut [MaybeUninit<u8>]);
    fn as_usize(&self) -> usize;
    fn from_u64(val: u64) -> Self;
    /// Convert the value from `endian` to the native endian.
    fn to_native_endian(&self, endian: impl object::Endian) -> Self;
    fn from_native_endian(&self, endian: impl object::Endian) -> Self;
}
impl BitWidth for u32 {
    unsafe fn from_bytes(bytes: &[u8], endian: impl object::Endian) -> Self {
        endian.read_u32_bytes(*(bytes.as_ptr() as *const [u8; 4]))
    }
    unsafe fn to_bytes(&self, endian: impl object::Endian, bytes: &mut [MaybeUninit<u8>]) {
        let arr = endian.write_u32_bytes(*self);
        bytes[0].as_mut_ptr().copy_from(arr.as_ptr(), 4);
    }
    fn as_usize(&self) -> usize {
        *self as usize
    }
    fn from_u64(val: u64) -> Self {
        Self::try_from(val).unwrap()
    }
    fn to_native_endian(&self, endian: impl object::Endian) -> Self {
        endian.read_u32(*self)
    }
    fn from_native_endian(&self, endian: impl object::Endian) -> Self {
        endian.write_u32(*self)
    }
}
impl BitWidth for u64 {
    unsafe fn from_bytes(bytes: &[u8], endian: impl object::Endian) -> Self {
        endian.read_u64_bytes(*(bytes.as_ptr() as *const [u8; 8]))
    }
    unsafe fn to_bytes(&self, endian: impl object::Endian, bytes: &mut [MaybeUninit<u8>]) {
        let arr = endian.write_u64_bytes(*self);
        bytes[0].as_mut_ptr().copy_from(arr.as_ptr(), 8);
    }
    fn as_usize(&self) -> usize {
        *self as usize
    }
    fn from_u64(val: u64) -> Self {
        val
    }
    fn to_native_endian(&self, endian: impl object::Endian) -> Self {
        endian.read_u64(*self)
    }
    fn from_native_endian(&self, endian: impl object::Endian) -> Self {
        endian.write_u64(*self)
    }
}

trait EndiannessExt {
    /// Split the slice at the given index.
    ///
    /// Returns a tuple of the slice up to the index as a fixed-size array, if the slice is long
    /// enough, and the rest of the slice.
    fn read_bits<T: BitWidth>(&self, data: &mut &[u8]) -> Option<T>;
    fn write_bits<T: BitWidth>(&self, value: T, data: &mut Vec<u8>);
    fn to_endianness(&self) -> object::Endianness;
}

impl<T: object::Endian> EndiannessExt for T {
    fn read_bits<Output: BitWidth>(&self, data: &mut &[u8]) -> Option<Output> {
        if data.len() < std::mem::size_of::<Output>() {
            None
        } else {
            // SAFETY: we just checked that the slice is long enough
            unsafe {
                let (a, b) = data.split_at_unchecked(std::mem::size_of::<Output>());
                *data = b;
                Some(Output::from_bytes(a, *self))
            }
        }
    }
    fn write_bits<'a, Output: BitWidth>(&self, value: Output, data: &mut Vec<u8>) {
        data.reserve(std::mem::size_of::<Output>());
        // SAFETY: we just made sure that the slice is long enough
        unsafe {
            let rest = data.spare_capacity_mut();
            value.to_bytes(*self, rest);
            data.set_len(data.len() + std::mem::size_of::<Output>());
        }
    }
    fn to_endianness(&self) -> object::Endianness {
        if self.is_big_endian() {
            object::Endianness::Big
        } else {
            object::Endianness::Little
        }
    }
}

struct NotesIter<'a, F: FileHeader>(object::read::elf::NoteIterator<'a, F>);

impl<'a, F: FileHeader> Iterator for NotesIter<'a, F> {
    type Item = std::result::Result<object::read::elf::Note<'a, F>, object::Error>;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().transpose()
    }
}

fn find_dt_debug_vaddr<F: FileHeader>(elf: &ElfFile<F>) -> Option<u64> {
    let (ph, d) = elf.elf_program_headers().iter().find_map(|ph| {
        ph.dynamic(elf.endian(), elf.data())
            .ok()
            .flatten()
            .map(|d| (ph, d))
    })?;
    let vaddr = ph.p_vaddr(elf.endian()).into();
    let data = ph.data(elf.endian(), elf.data()).ok()?;
    log::debug!(
        "Found dynamic section, vaddr {:x}, size {:x}",
        vaddr,
        ph.p_memsz(elf.endian()).into()
    );
    let mut offset = 0;
    while offset < data.len() {
        let (dyn_, _): (&F::Dyn, _) = object::pod::from_bytes(&data[offset..]).ok()?;
        log::debug!(
            "{:?}: {}, vaddr: {:x}",
            elf::to_str::d_tag_to_str(dyn_.d_tag(elf.endian()).into() as _),
            dyn_.d_val(elf.endian()).into(),
            offset as u64 + vaddr,
        );
        if dyn_.d_tag(elf.endian()).into() == object::elf::DT_DEBUG as u64 {
            return Some(
                offset as u64 + vaddr + /*skip d_tag*/elf.architecture().address_size().unwrap() as u64,
            );
        }
        offset += std::mem::size_of::<F::Dyn>();
    }
    None
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RDebug<Ptr: BitWidth> {
    r_version: u32,
    r_map: Ptr,
    r_brk: Ptr,
    r_state: u32,
    r_ldbase: Ptr,
}

impl<Ptr: BitWidth + Into<u64> + Copy> std::fmt::Debug for RDebug<Ptr> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RDebug")
            .field("r_version", &self.r_version)
            .field("r_map", &self.r_map.into())
            .field("r_brk", &self.r_brk.into())
            .field("r_state", &self.r_state)
            .field("r_ldbase", &self.r_ldbase.into())
            .finish()
    }
}

#[repr(C)]
#[derive(Debug)]
struct RawLinkMap<Ptr: BitWidth> {
    l_addr: Ptr,
    l_name: Ptr,
    l_ld: Ptr,
    l_next: Ptr,
    l_prev: Ptr,
}

#[derive(Debug)]
struct LinkMap {
    addr: u64,
    name: Vec<u8>,
    ld: u64,
    next: u64,
    prev: u64,
}

impl LinkMap {
    fn write<Ptr: BitWidth>(
        &self,
        endian: impl object::Endian,
        data: &mut Vec<u8>,
        base_addr: u64,
        is_last: bool,
    ) -> usize {
        let initial_len = data.len();
        let expected_len =
            initial_len + std::mem::size_of::<RawLinkMap<Ptr>>() + self.name.len() + 1;
        let expected_len =
            (expected_len + std::mem::align_of::<Ptr>() - 1) & !(std::mem::align_of::<Ptr>() - 1);
        endian.write_bits(Ptr::from_u64(self.addr), data);
        endian.write_bits(
            Ptr::from_u64(base_addr + std::mem::size_of::<RawLinkMap<Ptr>>() as u64),
            data,
        );
        endian.write_bits(Ptr::from_u64(self.ld), data);
        let next = if is_last {
            0
        } else {
            (expected_len - initial_len) as u64 + base_addr
        };
        log::info!("next: {:x}, prev: {:x}", next, self.prev);
        endian.write_bits(Ptr::from_u64(next), data);
        endian.write_bits(Ptr::from_u64(self.prev), data);
        data.extend(&self.name);
        data.push(0);
        let align = std::mem::align_of::<Ptr>();
        let padding = (align - data.len() % align) % align;
        data.extend(std::iter::repeat(0).take(padding));

        assert_eq!(data.len(), expected_len);
        data.len() - initial_len
    }
}

explicitly_size!(RDebug<u32>);
explicitly_size!(RDebug<u64>);

unsafe impl<Ptr: BitWidth> vm::Pod for RDebug<Ptr>
where
    Self: vm::ExplicitlySized,
{
    fn fix_endian(&mut self, endian: impl object::Endian) {
        self.r_version = self.r_version.to_native_endian(endian);
        self.r_map = self.r_map.to_native_endian(endian);
        self.r_brk = self.r_brk.to_native_endian(endian);
        self.r_state = self.r_state.to_native_endian(endian);
        self.r_ldbase = self.r_ldbase.to_native_endian(endian);
    }
    fn as_bytes(&self, endian: impl object::Endian) -> <Self as vm::ExplicitlySized>::CopyArr<u8> {
        let foreign_endian = Self {
            r_version: self.r_version.from_native_endian(endian),
            r_map: self.r_map.from_native_endian(endian),
            r_brk: self.r_brk.from_native_endian(endian),
            r_state: self.r_state.from_native_endian(endian),
            r_ldbase: self.r_ldbase.from_native_endian(endian),
        };
        unsafe { *(&foreign_endian as *const _ as *const _) }
    }
}

explicitly_size!(RawLinkMap<u32>);
explicitly_size!(RawLinkMap<u64>);

unsafe impl<Ptr: BitWidth> vm::Pod for RawLinkMap<Ptr>
where
    Self: vm::ExplicitlySized,
{
    fn fix_endian(&mut self, endian: impl object::Endian) {
        self.l_addr = self.l_addr.to_native_endian(endian);
        self.l_name = self.l_name.to_native_endian(endian);
        self.l_ld = self.l_ld.to_native_endian(endian);
        self.l_next = self.l_next.to_native_endian(endian);
        self.l_prev = self.l_prev.to_native_endian(endian);
    }
    fn as_bytes(&self, _endian: impl object::Endian) -> <Self as vm::ExplicitlySized>::CopyArr<u8> {
        unimplemented!("Don't write RawLinkMap directly, use LinkMap::write")
    }
}

fn handle_elf<F: object::read::elf::FileHeader>(
    elf: &ElfFile<F>,
    base_dir: impl AsRef<Path>,
) -> Result<()>
where
    <F as FileHeader>::Word: Copy + TryFrom<usize> + TryFrom<u64> + BitWidth,
    RDebug<F::Word>: vm::Pod,
    RawLinkMap<F::Word>: vm::Pod,
    <<F as FileHeader>::Word as TryFrom<u64>>::Error: std::error::Error + Send + Sync,
    <<F as FileHeader>::Word as TryFrom<usize>>::Error: std::error::Error + Send + Sync,
{
    let mut nt_file: Option<notes::nt_file::NtFileAny<'_>> = None;
    let mut fname = None;
    for ph in elf.elf_program_headers() {
        let notes = ph.notes(elf.endian(), elf.data())?;
        if let Some(notes) = notes {
            for note in NotesIter(notes) {
                let note = note?;
                if note.n_type(elf.endian()) == object::elf::NT_PRPSINFO {
                    let info = notes::nt_prpsinfo::PsInfo::parse(&note, elf.endian());
                    log::info!("fname is: {}", std::str::from_utf8(info.fname).unwrap());
                    fname = Some(info.fname);
                    continue;
                }
                if note.n_type(elf.endian()) != object::elf::NT_FILE {
                    continue;
                }
                if nt_file.is_some() {
                    return Err(anyhow::anyhow!("Mutiple NT_FILE notes found in core"));
                }
                nt_file = Some(notes::nt_file::NtFileAny::parse(&note, elf.endian())?);
            }
        }
    }

    let Some(nt_file) = nt_file else {
        return Err(anyhow::anyhow!("No NT_FILE note found in core"));
    };
    let Some(fname) = fname else {
        return Err(anyhow::anyhow!("No NT_PRPSINFO note found in core"));
    };
    let nul_pos = fname.iter().position(|&b| b == 0).unwrap_or(fname.len());
    let fname = &fname[..nul_pos];

    let base_dir = base_dir.as_ref();
    let mut copied = HashSet::<PathBuf>::new();
    let Some(main_exec) = nt_file.files().find(|f| {
        let src_path = std::path::Path::new(OsStr::from_bytes(f.file()));
        let Some(filename) = src_path.file_name() else {
            return false;
        };
        if filename.as_bytes().starts_with(fname) {
            return true;
        }
        false
    }) else {
        return Err(anyhow::anyhow!(
            "Couldn't find main executable in NT_FILE notes"
        ));
    };
    log::info!(
        "Main executable is: {}",
        std::str::from_utf8(main_exec.file())?
    );

    let main_exec = Path::new(OsStr::from_bytes(main_exec.file()));
    if main_exec.parent().unwrap() != base_dir {
        let path = base_dir.join(main_exec.file_name().unwrap());
        log::info!("Copying {} to {}", main_exec.display(), path.display());
        std::fs::copy(main_exec, &path).unwrap_or_else(|e| {
            log::error!(
                "Couldn't copy file from {} to {}: {e}",
                main_exec.display(),
                path.display()
            );
            0
        });
        if path.exists() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).ok();
        }
        copied.insert(main_exec.to_path_buf());
    }
    let main_exec = std::fs::read(main_exec)?;
    let main_exec = object::File::parse(&*main_exec)?;
    let Some(dt_debug) = (match &main_exec {
        object::File::Elf32(elf) => find_dt_debug_vaddr(elf),
        object::File::Elf64(elf) => find_dt_debug_vaddr(elf),
        _ => None,
    }) else {
        return Err(anyhow::anyhow!("Couldn't find DT_DEBUG in main executable"));
    };
    log::info!("vaddr of DT_DEBUG is: {:x}", dt_debug);

    let vm = vm::Vm::load_object(elf)?;
    let r_debug = vm.read_ptr(dt_debug, elf.endian())?;
    let mut r_debug = vm.read_pod::<RDebug<F::Word>>(r_debug, elf.endian())?;
    log::info!("r_debug: {:x?}", r_debug);
    let mut link_map = r_debug.r_map;
    let mut name_buf = Vec::new();
    let mut link_map_size = std::mem::size_of::<RDebug<F::Word>>();
    let mut link_maps = Vec::new();
    while link_map.into() != 0 {
        let raw_lmap = vm.read_pod::<RawLinkMap<F::Word>>(link_map.into(), elf.endian())?;
        vm.read_until_nul(raw_lmap.l_name.into(), &mut name_buf)?;
        let lmap = LinkMap {
            addr: raw_lmap.l_addr.into(),
            name: name_buf.clone(),
            ld: raw_lmap.l_ld.into(),
            next: raw_lmap.l_next.into(),
            prev: raw_lmap.l_prev.into(),
        };
        log::info!(
            "link_map: {lmap:x?}, file name: {:?}",
            std::str::from_utf8(&name_buf)
        );
        link_maps.push(lmap);
        link_map = raw_lmap.l_next;

        let src_path = std::path::Path::new(OsStr::from_bytes(&name_buf));
        let Some(filename) = src_path.file_name() else {
            continue;
        };
        let Some(parent) = src_path.parent() else {
            continue;
        };
        let path = if parent != base_dir {
            base_dir.join(filename)
        } else {
            src_path.to_path_buf()
        };
        if !copied.contains(src_path) {
            if src_path != path {
                log::info!("Copying {} to {}", src_path.display(), path.display());
                std::fs::copy(src_path, &path).unwrap_or_else(|e| {
                    log::error!(
                        "Couldn't copy file from {} to {}: {e}",
                        src_path.display(),
                        path.display()
                    );
                    0
                });
                if path.exists() {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).ok();
                }
            }
            copied.insert(src_path.to_path_buf());
        }
    }

    for lmap in link_maps.iter_mut() {
        let src_path = std::path::Path::new(OsStr::from_bytes(&lmap.name));
        if let Some(parent) = src_path.parent() {
            if let Some(filename) = src_path.file_name() {
                if parent != base_dir {
                    lmap.name = base_dir.join(filename).as_os_str().as_bytes().to_vec();
                }
            }
        }
        link_map_size += std::mem::size_of::<RawLinkMap<F::Word>>()
            + vm.align_to_ptr(lmap.name.len() as u64 + 1) as usize;
    }
    // Synthesize a new link_map and replace the file names.
    // First, find a free address range.
    let free_addr = vm.find_free(link_map_size as u64).ok_or_else(|| {
        anyhow::anyhow!("Couldn't find a free address range for the new link_map")
    })?;
    let mut link_map_end = free_addr;
    log::info!(
        "Free address range: {:x}, size needed: {}, link map entries {}",
        link_map_end,
        link_map_size,
        link_maps.len()
    );
    r_debug.r_map = <F as FileHeader>::Word::try_from(
        free_addr + std::mem::size_of::<RDebug<F::Word>>() as u64,
    )
    .unwrap();
    link_map_end = free_addr + std::mem::size_of::<RDebug<F::Word>>() as u64;

    let mut new_link_map = Vec::new();
    new_link_map.extend_from_slice(r_debug.as_bytes(elf.endian()).as_ref());
    let mut prev = 0;
    let link_maps_len = link_maps.len();
    for (i, lmap) in link_maps.iter_mut().enumerate() {
        lmap.prev = prev;
        prev = link_map_end;
        let size = lmap.write::<F::Word>(
            elf.endian(),
            &mut new_link_map,
            link_map_end,
            i == link_maps_len - 1,
        );
        link_map_end += size as u64;
    }
    log::info!(
        "Link map end: {:x}, actual size: {}",
        link_map_end,
        link_map_end - free_addr
    );

    let output_file = std::fs::File::create(base_dir.join("core"))?;
    let mut output_file = object::write::StreamingBuffer::new(output_file);
    let mut writer = object::write::elf::Writer::new(
        elf.endian().to_endianness(),
        F::is_type_64_sized(),
        &mut output_file,
    );
    let fh = elf.elf_header();
    let endian = elf.endian();
    writer.reserve_file_header();
    log::info!("Header size: {}", writer.reserved_len());
    writer.reserve_program_headers((fh.e_phnum(endian) + 1) as _);
    log::info!("Program headers size: {}", writer.reserved_len());
    writer.write_file_header(&object::write::elf::FileHeader {
        abi_version: fh.e_ident().abi_version,
        os_abi: fh.e_ident().os_abi,
        e_type: fh.e_type(endian),
        e_machine: fh.e_machine(endian),
        e_entry: fh.e_entry(endian).into(),
        e_flags: fh.e_flags(endian),
    })?;
    let mut curr_offset = writer.reserved_len() as u64;
    for ph in elf.elf_program_headers() {
        let align = ph.p_align(endian).into();
        if align > 0 {
            curr_offset = (curr_offset + align - 1) & !(align - 1);
        }
        writer.write_program_header(&object::write::elf::ProgramHeader {
            p_type: ph.p_type(endian),
            p_flags: ph.p_flags(endian),
            p_offset: curr_offset,
            p_vaddr: ph.p_vaddr(endian).into(),
            p_paddr: ph.p_paddr(endian).into(),
            p_filesz: ph.p_filesz(endian).into(),
            p_memsz: ph.p_memsz(endian).into(),
            p_align: ph.p_align(endian).into(),
        });
        curr_offset += ph.p_filesz(endian).into();
    }
    let curr_offset = (curr_offset + 4095) & !4095;
    writer.write_program_header(&object::write::elf::ProgramHeader {
        p_type: object::elf::PT_LOAD,
        p_flags: object::elf::PF_R | object::elf::PF_W,
        p_offset: curr_offset,
        p_vaddr: free_addr,
        p_paddr: 0,
        p_filesz: (link_map_end - free_addr) as u64,
        p_memsz: ((link_map_end - free_addr) as u64 + 4095) & !4095,
        p_align: 4096,
    });
    for ph in elf.elf_program_headers() {
        writer.write_align(<F as FileHeader>::Word::into(ph.p_align(endian)) as _);
        let vaddr = ph.p_vaddr(endian).into();
        let memsz = ph.p_memsz(endian).into();
        if vaddr <= dt_debug && vaddr + memsz > dt_debug {
            // Overwrite the DT_DEBUG pointer.
            let mut data_copy = ph.data(endian, elf.data()).unwrap().to_vec();
            let offset = (dt_debug - vaddr) as usize;
            let ptr_size = std::mem::size_of::<F::Word>();
            let ptr = <F as FileHeader>::Word::try_from(free_addr).unwrap();
            unsafe {
                ptr.to_bytes(
                    endian,
                    &mut *(&mut data_copy[offset..offset + ptr_size] as *mut _ as *mut _),
                );
            }
            writer.write(&data_copy);
        } else {
            writer.write(ph.data(endian, elf.data()).unwrap())
        }
    }
    writer.write_align(4096);
    writer.write(&new_link_map);

    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    if std::env::args().len() != 3 {
        eprintln!(
            "Usage: {} <input> <output dir>",
            std::env::args().next().unwrap()
        );
        eprintln!();
        eprintln!("Copy a core file and all its dependencies into <output dir>.");
        eprintln!("Rewrite paths in the core file to use the copied files.");
        return Ok(());
    }
    let filename = std::env::args().nth(1).unwrap();
    let filename = Path::new(&filename);
    let basedir = std::env::args().nth(2).unwrap();
    let basedir = Path::new(&basedir);
    if filename
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid input file path"))?
        == basedir
    {
        return Err(anyhow::anyhow!("Source and destination is the same file"));
    }
    std::fs::create_dir_all(basedir)?;
    let data = std::fs::read(filename)?;
    let obj = object::File::parse(&*data)?;

    match obj {
        object::File::Elf32(elf) => handle_elf(&elf, basedir),
        object::File::Elf64(elf) => handle_elf(&elf, basedir),
        _ => Err(anyhow::anyhow!("unsupported object file format")),
    }
}
