use std::{
    collections::HashSet,
    ffi::OsStr,
    fmt::{Display, LowerHex},
    mem::MaybeUninit,
    ops::{Add, AddAssign, BitAnd, Not, Sub},
    os::unix::{ffi::OsStrExt as _, fs::PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::Result;
use object::read::elf::{ElfFile, FileHeader, ProgramHeader};

trait BitWidth {
    /// SAFETY: the slice must be at least `Self::BYTES` long.
    unsafe fn from_bytes(bytes: &[u8], endian: impl object::Endian) -> Self;
    /// SAFETY: the slice must be at least `Self::BYTES` long.
    unsafe fn to_bytes(&self, endian: impl object::Endian, bytes: &mut [MaybeUninit<u8>]);
    fn as_usize(&self) -> usize;
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

struct MappedFile<T> {
    start: T,
    end: T,
    offset: T,
    file: Vec<u8>,
}

enum MappedFileAny<'a> {
    MappedFile64(&'a mut MappedFile<u64>),
    MappedFile32(&'a mut MappedFile<u32>),
}

impl<'a> MappedFileAny<'a> {
    fn file_mut(self) -> &'a mut Vec<u8> {
        match self {
            MappedFileAny::MappedFile32(m) => &mut m.file,
            MappedFileAny::MappedFile64(m) => &mut m.file,
        }
    }
    fn as_mut(&mut self) -> MappedFileAny<'_> {
        match self {
            MappedFileAny::MappedFile32(m) => MappedFileAny::MappedFile32(m),
            MappedFileAny::MappedFile64(m) => MappedFileAny::MappedFile64(m),
        }
    }
}

struct NtFile<'data, T> {
    count: T,
    pagesz: T,
    name: &'data [u8],
    files: Vec<MappedFile<T>>,
}

enum NtFileAny<'data> {
    NtFile32(NtFile<'data, u32>),
    NtFile64(NtFile<'data, u64>),
}

impl<'data> From<NtFile<'data, u32>> for NtFileAny<'data> {
    fn from(nt_file: NtFile<'data, u32>) -> Self {
        NtFileAny::NtFile32(nt_file)
    }
}
impl<'data> From<NtFile<'data, u64>> for NtFileAny<'data> {
    fn from(nt_file: NtFile<'data, u64>) -> Self {
        NtFileAny::NtFile64(nt_file)
    }
}

fn parse_nt_file<'data, T: BitWidth + Display, Elf: FileHeader>(
    endian: <Elf as FileHeader>::Endian,
    note: &object::read::elf::Note<'data, Elf>,
) -> Result<NtFile<'data, T>> {
    let mut data = note.desc();
    let count = endian
        .read_bits::<T>(&mut data)
        .ok_or_else(|| anyhow::anyhow!("not enough data"))?;
    let pagesz = endian
        .read_bits::<T>(&mut data)
        .ok_or_else(|| anyhow::anyhow!("not enough data"))?;
    let mut files = Vec::new();
    for _ in 0..count.as_usize() {
        let start = endian
            .read_bits::<T>(&mut data)
            .ok_or_else(|| anyhow::anyhow!("not enough data"))?;
        let end = endian
            .read_bits::<T>(&mut data)
            .ok_or_else(|| anyhow::anyhow!("not enough data"))?;
        let offset = endian
            .read_bits::<T>(&mut data)
            .ok_or_else(|| anyhow::anyhow!("not enough data"))?;
        files.push(MappedFile {
            start,
            end,
            offset,
            file: vec![],
        });
    }
    for file in &mut files {
        let file_name = std::ffi::CStr::from_bytes_until_nul(data)?;
        data = &data[file_name.to_bytes().len() + 1..];
        file.file = file_name.to_bytes().to_vec();
    }
    Ok(NtFile {
        count,
        pagesz,
        name: note.name(),
        files,
    })
}

fn serialize_nt_note<T: BitWidth + Copy>(
    endian: impl object::Endian,
    notes: &NtFile<'_, T>,
    data: &mut Vec<u8>,
) {
    endian.write_bits((notes.name.len() + 1) as u32, data);
    let descsz_offset = data.len();
    endian.write_bits(0u32, data); // Set descsz to 0 for now
    endian.write_bits(object::elf::NT_FILE, data);
    data.extend_from_slice(notes.name);
    data.push(0);
    let padding = (4 - data.len() % 4) % 4;
    data.extend(std::iter::repeat(0).take(padding));

    let len1 = data.len();
    assert_eq!(len1 % 4, 0);

    endian.write_bits(notes.count, data);
    endian.write_bits(notes.pagesz, data);
    for file in &notes.files {
        endian.write_bits(file.start, data);
        endian.write_bits(file.end, data);
        endian.write_bits(file.offset, data);
    }
    for file in &notes.files {
        data.extend_from_slice(&file.file);
        data.push(0);
    }

    let descsz = data.len() - len1;
    let padding = (4 - (descsz % 4)) % 4;
    data.extend(std::iter::repeat(0).take(padding));
    data[descsz_offset..descsz_offset + 4]
        .copy_from_slice(&endian.write_u32_bytes(descsz as u32)[..]);
}
impl NtFileAny<'_> {
    fn serialize(&self, endian: impl object::Endian, data: &mut Vec<u8>) {
        match self {
            NtFileAny::NtFile32(nt_file) => serialize_nt_note(endian, nt_file, data),
            NtFileAny::NtFile64(nt_file) => serialize_nt_note(endian, nt_file, data),
        }
    }
    fn files_mut(&mut self) -> impl Iterator<Item = MappedFileAny<'_>> {
        enum NtFilesIter<A, B> {
            A(A),
            B(B),
        }
        impl<'a, A: Iterator<Item = MappedFileAny<'a>>, B: Iterator<Item = MappedFileAny<'a>>>
            Iterator for NtFilesIter<A, B>
        {
            type Item = MappedFileAny<'a>;
            fn next(&mut self) -> Option<Self::Item> {
                match self {
                    Self::A(a) => a.next(),
                    Self::B(b) => b.next(),
                }
            }
        }
        match self {
            NtFileAny::NtFile32(f) => {
                NtFilesIter::A(f.files.iter_mut().map(MappedFileAny::MappedFile32))
            }
            NtFileAny::NtFile64(f) => {
                NtFilesIter::B(f.files.iter_mut().map(MappedFileAny::MappedFile64))
            }
        }
    }
}

trait ZeroOne {
    fn zero() -> Self;
    fn one() -> Self;
}

impl ZeroOne for u64 {
    fn zero() -> Self {
        0
    }
    fn one() -> Self {
        1
    }
}

impl ZeroOne for u32 {
    fn one() -> Self {
        1
    }
    fn zero() -> Self {
        0
    }
}

#[link(name = "patchelf")]
#[link(name = "stdc++")]
extern "C" {
    fn patchelf_run() -> bool;
    fn patchelf_set_input(name: *const i8);
    fn patchelf_set_rpath(name: *const i8);
    fn patchelf_clear();
}

fn get_soname(file: impl AsRef<Path>) -> Option<Vec<u8>> {
    let file = file.as_ref();
    let data = std::fs::read(file).ok()?;
    let file = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data).ok()?;
    let mut soname = None;
    let mut strtab_vaddr = None;
    for dt in file.dynamic().ok().flatten()?.iter() {
        if dt.d_tag == elf::abi::DT_STRTAB {
            log::info!("Found STRTAB: {:x}", dt.clone().d_ptr());
            strtab_vaddr = Some(dt.d_ptr());
        }
    }
    let strtab_vaddr = strtab_vaddr?;
    let mut strtab = None;
    for sh in file.section_headers()?.iter() {
        if sh.sh_addr == strtab_vaddr {
            strtab = Some(file.section_data_as_strtab(&sh).ok()?);
        }
    }
    let strtab = strtab?;
    for dt in file.dynamic().ok().flatten()?.iter() {
        if dt.d_tag == elf::abi::DT_SONAME {
            let name = strtab.get_raw(dt.d_val() as usize).ok()?;
            soname = Some(name.to_vec());
            log::info!("Found SONAME: {:?}", std::str::from_utf8(name));
            break;
        }
    }
    soname
}

struct NotesIter<'a, F: FileHeader>(object::read::elf::NoteIterator<'a, F>);

impl<'a, F: FileHeader> Iterator for NotesIter<'a, F> {
    type Item = std::result::Result<object::read::elf::Note<'a, F>, object::Error>;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().transpose()
    }
}

fn handle_elf<F: object::read::elf::FileHeader>(
    elf: &ElfFile<F>,
    base_dir: impl AsRef<Path>,
) -> Result<()>
where
    <F as FileHeader>::Word: Copy
        + AddAssign
        + Add<Output = <F as FileHeader>::Word>
        + BitAnd<Output = <F as FileHeader>::Word>
        + PartialOrd
        + Sub<Output = <F as FileHeader>::Word>
        + Not<Output = <F as FileHeader>::Word>
        + ZeroOne
        + LowerHex
        + TryFrom<usize>,
    <<F as FileHeader>::Word as TryFrom<usize>>::Error: std::error::Error + Send + Sync,
{
    let mut nt_file: Option<NtFileAny<'_>> = None;
    let first_offset = elf.elf_program_headers()[0].p_offset(elf.endian());
    for ph in elf.elf_program_headers() {
        let notes = ph.notes(elf.endian(), elf.data())?;
        if let Some(notes) = notes {
            for note in NotesIter(notes) {
                let note = note?;
                if note.n_type(elf.endian()) != object::elf::NT_FILE {
                    continue;
                }
                if nt_file.is_some() {
                    return Err(anyhow::anyhow!("Mutiple NT_FILE notes found in core"));
                }
                nt_file = Some(if F::is_type_64_sized() {
                    parse_nt_file::<u64, _>(elf.endian(), &note)?.into()
                } else {
                    parse_nt_file::<u32, _>(elf.endian(), &note)?.into()
                });
            }
        }
    }

    let base_dir = base_dir.as_ref();
    if let Some(nt_file) = nt_file.as_mut() {
        let mut copied = HashSet::<PathBuf>::new();
        for mut file in nt_file.files_mut() {
            let src_path = std::path::Path::new(OsStr::from_bytes(file.as_mut().file_mut()));
            let Some(parent) = src_path.parent() else {
                continue;
            };
            let Some(filename) = src_path.file_name() else {
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
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
                        if let Some(soname) = get_soname(&path) {
                            if filename.as_bytes() != &soname {
                                let target = base_dir.join(OsStr::from_bytes(&soname));
                                std::os::unix::fs::symlink(filename, &target).unwrap_or_else(|e| {
                                    log::error!(
                                        "Couldn't create symlink from {:?} to {}: {e}",
                                        filename,
                                        target.display()
                                    );
                                });
                            }
                        }
                        unsafe {
                            let cpath =
                                std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                            patchelf_set_input(cpath.as_ptr());
                            patchelf_set_rpath(c"$ORIGIN".as_ptr() as *const i8);
                            patchelf_run();
                            patchelf_clear();
                        }
                    }
                }
                copied.insert(src_path.to_path_buf());
            }
            *file.file_mut() = path.as_os_str().as_bytes().to_vec();
        }
    }

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
    writer.reserve_program_headers(fh.e_phnum(endian) as _);
    writer.write_file_header(&object::write::elf::FileHeader {
        abi_version: fh.e_ident().abi_version,
        os_abi: fh.e_ident().os_abi,
        e_type: fh.e_type(endian),
        e_machine: fh.e_machine(endian),
        e_entry: fh.e_entry(endian).into(),
        e_flags: fh.e_flags(endian),
    })?;
    let mut curr_offset = first_offset;
    let mut notes_data = Vec::new();
    for ph in elf.elf_program_headers() {
        let notes = ph.notes(elf.endian(), elf.data())?;
        if let Some(notes) = notes {
            for note in NotesIter(notes) {
                let note = note?;
                if note.n_type(elf.endian()) != object::elf::NT_FILE {
                    endian.write_bits(note.n_namesz(endian), &mut notes_data);
                    endian.write_bits(note.n_descsz(endian), &mut notes_data);
                    endian.write_bits(note.n_type(endian), &mut notes_data);
                    notes_data.extend_from_slice(note.name());
                    notes_data.push(0);
                    let padding = (4 - (note.name().len() + 1) % 4) % 4;
                    notes_data.extend(std::iter::repeat(0).take(padding));
                    notes_data.extend_from_slice(note.desc());
                    let padding = (4 - note.desc().len() % 4) % 4;
                    notes_data.extend(std::iter::repeat(0).take(padding));
                    assert_eq!(notes_data.len() % 4, 0);
                    continue;
                }
                let notes = nt_file.as_ref().unwrap();
                notes.serialize(elf.endian(), &mut notes_data);
                assert_eq!(notes_data.len() % 4, 0);
            }
            writer.write_program_header(&object::write::elf::ProgramHeader {
                p_type: object::elf::PT_NOTE,
                p_flags: 0,
                p_offset: curr_offset.into(),
                p_vaddr: 0,
                p_paddr: 0,
                p_filesz: notes_data.len() as _,
                p_memsz: 0,
                p_align: 0,
            });
            curr_offset += <F as FileHeader>::Word::try_from(notes_data.len())?;
        } else {
            let align = ph.p_align(endian);
            let zero = <F as FileHeader>::Word::zero();
            let one = <F as FileHeader>::Word::one();
            if align > zero {
                curr_offset = (curr_offset + align - one) & !(align - one);
            }
            writer.write_program_header(&object::write::elf::ProgramHeader {
                p_type: ph.p_type(endian),
                p_flags: ph.p_flags(endian),
                p_offset: curr_offset.into(),
                p_vaddr: ph.p_vaddr(endian).into(),
                p_paddr: ph.p_paddr(endian).into(),
                p_filesz: ph.p_filesz(endian).into(),
                p_memsz: ph.p_memsz(endian).into(),
                p_align: ph.p_align(endian).into(),
            });
            curr_offset += ph.p_filesz(endian);
        }
    }
    for ph in elf.elf_program_headers() {
        let notes = ph.notes(elf.endian(), elf.data())?;
        if notes.is_some() {
            writer.write(&notes_data);
        } else {
            writer.write_align(<F as FileHeader>::Word::into(ph.p_align(endian)) as _);
            writer.write(ph.data(endian, elf.data()).unwrap())
        }
    }
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
