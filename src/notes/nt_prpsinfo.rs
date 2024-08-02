// C version of prpsinfo:
//
// struct elf_prpsinfo
// {
//     char pr_state; /* numeric process state */
//     char pr_sname; /* char for pr_state */
//     char pr_zomb; /* zombie */
//     char pr_nice; /* nice val */
//     unsigned long pr_flag; /* flags */
//     __kernel_uid_t pr_uid;
//     __kernel_gid_t pr_gid;
//     pid_t pr_pid, pr_ppid, pr_pgrp, pr_sid;
//     /* Lots missing */
//     /*
//      * The hard-coded 16 is derived from TASK_COMM_LEN, but it can't be
//      * changed as it is exposed to userspace. We'd better make it hard-coded
//      * here.
//      */
//     char pr_fname[16]; /* filename of executable */
//     char pr_psargs[ELF_PRARGSZ]; /* initial part of arg list */
// };

use object::read::elf::{FileHeader, Note};

const ELF_PRARGSZ: usize = 80;

pub struct PsInfo<'a> {
    pub fname: &'a [u8],
    pub psargs: &'a [u8],
}

impl<'a> PsInfo<'a> {
    pub fn parse<F: FileHeader>(note: &Note<'a, F>, endian: F::Endian) -> Self {
        assert!(note.n_type(endian) == object::elf::NT_PRPSINFO);
        let skip = 4 + if F::is_type_64_sized() { 4 /*padding*/ + 8 } else { 4 } + 4 + 4 + 4 * 4;
        let data = note.desc();
        Self {
            fname: &data[skip..skip + 16],
            psargs: &data[skip + 16..skip + 16 + ELF_PRARGSZ],
        }
    }
}
