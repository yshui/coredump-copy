//! Parser of NT_FILE notes

use crate::{BitWidth, EndiannessExt as _};
use anyhow::Result;
use object::read::elf::{FileHeader, Note};

#[derive(Debug)]
pub struct MappedFile<T> {
    start: T,
    end: T,
    offset: T,
    file: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub enum MappedFileAny<'a> {
    MappedFile64(&'a MappedFile<u64>),
    MappedFile32(&'a MappedFile<u32>),
}

impl<'a> MappedFileAny<'a> {
    pub fn file(self) -> &'a [u8] {
        match self {
            MappedFileAny::MappedFile32(m) => &m.file,
            MappedFileAny::MappedFile64(m) => &m.file,
        }
    }
}

pub struct NtFile<'data, T> {
    count: T,
    pagesz: T,
    name: &'data [u8],
    files: Vec<MappedFile<T>>,
}

pub enum NtFileAny<'data> {
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

fn parse_nt_file<'data, T: BitWidth + std::fmt::Display, Elf: FileHeader>(
    endian: <Elf as FileHeader>::Endian,
    note: &object::read::elf::Note<'data, Elf>,
) -> Result<NtFile<'data, T>> {
    assert!(note.n_type(endian) == object::elf::NT_FILE);
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
impl<'a> NtFileAny<'a> {
    pub fn serialize(&self, endian: impl object::Endian, data: &mut Vec<u8>) {
        match self {
            NtFileAny::NtFile32(nt_file) => serialize_nt_note(endian, nt_file, data),
            NtFileAny::NtFile64(nt_file) => serialize_nt_note(endian, nt_file, data),
        }
    }
    pub fn pagesz(&self) -> u64 {
        match self {
            NtFileAny::NtFile32(nt_file) => nt_file.pagesz as u64,
            NtFileAny::NtFile64(nt_file) => nt_file.pagesz,
        }
    }
    pub fn parse<'b, F: FileHeader>(note: &'b Note<'a, F>, endian: F::Endian) -> Result<Self> {
        if F::is_type_64_sized() {
            Ok(NtFileAny::NtFile64(parse_nt_file(endian, note)?))
        } else {
            Ok(NtFileAny::NtFile32(parse_nt_file(endian, note)?))
        }
    }
    pub fn files(&self) -> impl Iterator<Item = MappedFileAny<'_>> {
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
                NtFilesIter::A(f.files.iter().map(MappedFileAny::MappedFile32))
            }
            NtFileAny::NtFile64(f) => {
                NtFilesIter::B(f.files.iter().map(MappedFileAny::MappedFile64))
            }
        }
    }
}
