use crate::EndiannessExt as _;
use anyhow::Result;
use core::slice;
use object::{
    read::elf::{FileHeader, ProgramHeader as _},
    Object, ObjectSegment as _,
};
use std::{collections::BTreeMap, mem::MaybeUninit};

pub struct Segment<'a> {
    pub data: &'a [u8],
    pub memsz: u64,
}

impl<'a> Segment<'a> {
    fn read_into_uninit(&self, offset: u64, mut output: &mut [MaybeUninit<u8>]) -> Result<u64> {
        if output.is_empty() {
            return Ok(0);
        }
        if offset >= self.memsz {
            return Err(anyhow::anyhow!("Offset out of bounds"));
        }
        let mut offset2 = offset;
        let len = self.data.len() as u64;
        if offset2 < len {
            let to_read = (output.len() as u64).min(len - offset2);
            // SAFETY: we made sure `to_read` doesn't exceed the length of `self.data` or `output`.
            unsafe {
                output[0]
                    .as_mut_ptr()
                    .copy_from(self.data[offset2 as usize..].as_ptr(), to_read as usize);
            }
            output = &mut output[to_read as usize..];
            offset2 += to_read;
        }
        if !output.is_empty() && offset2 < self.memsz {
            let to_zero = (output.len() as u64).min(self.memsz - offset2);
            output[..to_zero as usize].fill(MaybeUninit::new(0));
            offset2 += to_zero;
        }
        Ok(offset2 - offset)
    }
}

/// Maps a elf file into memory, without _actually_ mapping it into memory.
pub struct Vm<'a> {
    vma: BTreeMap<u64, Segment<'a>>,
    addr_size: u8,
}

impl<'a> Vm<'a> {
    pub fn load_object<F: FileHeader>(obj: &object::read::elf::ElfFile<'a, F>) -> Result<Self> {
        let mut vma = BTreeMap::new();
        let addr_size = obj.architecture().address_size().unwrap() as u8;
        for segment in obj.elf_program_headers() {
            if segment.p_type(obj.endian()) != object::elf::PT_LOAD {
                continue;
            }
            vma.insert(
                segment.p_vaddr(obj.endian()).into(),
                Segment {
                    memsz: segment.p_memsz(obj.endian()).into(),
                    data: segment
                        .data(obj.endian(), obj.data())
                        .map_err(|_| anyhow::anyhow!("Failed to read segment"))?,
                },
            );
        }
        Ok(Vm { vma, addr_size })
    }
    pub fn read_into_uninit<'b>(
        &self,
        vaddr: u64,
        output_: &'b mut [MaybeUninit<u8>],
    ) -> Result<&'b mut [u8]> {
        if output_.is_empty() {
            return Ok(&mut []);
        }
        let mut output = &mut *output_;
        let first = self
            .vma
            .range(..=vaddr)
            .last()
            .ok_or_else(|| anyhow::anyhow!("No segments in VM"))?;
        if first.0 + first.1.memsz <= vaddr {
            return Err(anyhow::anyhow!("Address not in any segment"));
        }
        let read = first.1.read_into_uninit(vaddr - first.0, output)?;
        output = &mut output[read as usize..];
        let mut last_addr = first.0 + first.1.memsz;
        for range in self.vma.range(last_addr..) {
            if output.is_empty() {
                break;
            }
            if *range.0 != last_addr {
                return Err(anyhow::anyhow!("Read range has holes"));
            }
            let read = range.1.read_into_uninit(0, output)?;
            output = &mut output[read as usize..];
            last_addr = range.0 + range.1.memsz;
        }
        if output.is_empty() {
            // SAFETY: `output_` is completely filled.
            return Ok(unsafe { &mut *(output_ as *mut [_] as *mut [u8]) });
        }
        Err(anyhow::anyhow!("Not enough data in VM"))
    }
    pub fn read(&self, vaddr: u64, output: &mut [u8]) -> Result<()> {
        // SAFETY: `read_into_uninit` will not uninitialize an already initialized slice.
        let output = unsafe { &mut *(output as *mut _ as *mut [MaybeUninit<u8>]) };
        self.read_into_uninit(vaddr, output)?;
        Ok(())
    }
    /// Find the first occurrence of a byte, starting from `vaddr`. If `vaddr` is not a valid
    /// address, this function will return `None`.
    pub fn find_byte(&self, vaddr: u64, byte: u8) -> Option<u64> {
        let first = self.vma.range(..=vaddr).last()?;
        if first.0 + first.1.memsz <= vaddr {
            return None;
        }
        let slice = &first.1.data[(vaddr - first.0) as usize..];
        if let Some(pos) = slice.iter().position(|&b| b == byte) {
            return Some(vaddr + pos as u64);
        }
        if first.1.memsz > first.1.data.len() as u64 {
            return Some(first.0 + first.1.data.len() as u64 + 1);
        }
        let mut last_addr = first.0 + first.1.memsz;
        for range in self.vma.range(vaddr + slice.len() as u64..) {
            if *range.0 != last_addr {
                return None;
            }
            if let Some(pos) = range.1.data.iter().position(|&b| b == byte) {
                return Some(range.0 + pos as u64);
            }
            if range.1.memsz > range.1.data.len() as u64 {
                return Some(range.0 + range.1.data.len() as u64 + 1);
            }
            last_addr = range.0 + range.1.memsz;
        }
        None
    }
    pub fn read_until_nul(&self, vaddr: u64, output: &mut Vec<u8>) -> Result<()> {
        let end = self
            .find_byte(vaddr, 0)
            .ok_or_else(|| anyhow::anyhow!("No NUL byte found"))?;
        log::info!("Read {:x} - {:x}", vaddr, end);
        output.clear();
        if end == vaddr {
            return Ok(());
        }
        output.reserve((end - vaddr) as usize);
        self.read_into_uninit(
            vaddr,
            &mut output.spare_capacity_mut()[..(end - vaddr) as usize],
        )?;
        unsafe {
            output.set_len((end - vaddr) as usize);
        }
        Ok(())
    }
    pub fn read_ptr(&self, vaddr: u64, endian: impl object::Endian) -> Result<u64> {
        let mut buf = [0; 8];
        self.read(vaddr, &mut buf[..self.addr_size as usize])?;
        let mut buf = &buf[..self.addr_size as usize];
        Ok(match self.addr_size {
            4 => endian.read_bits::<u32>(&mut buf).unwrap() as u64,
            8 => endian.read_bits::<u64>(&mut buf).unwrap(),
            _ => unreachable!(),
        })
    }
    pub fn align_to_ptr(&self, vaddr: u64) -> u64 {
        (vaddr + self.addr_size as u64 - 1) & !(self.addr_size as u64 - 1)
    }
    /// Find a free region of memory of at least `size` bytes. The start address will be page aligned.
    pub fn find_free(&self, size: u64) -> Option<u64> {
        for (curr, next) in self.vma.iter().zip(self.vma.iter().skip(1)) {
            const PAGE_SIZE: u64 = 4096;
            let curr_end = curr.0 + curr.1.memsz;
            let curr_end = (curr_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            let next_start = next.0;
            if next_start - curr_end >= size {
                return Some(curr_end);
            }
        }
        None
    }
}
