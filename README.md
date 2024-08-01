coredump-copy
=============

# Usage

```
coredump-copy <input> <output-dir>
```


- `<input>`: The core dump file to copy. This will copy the core dump file along with all the files it reference. The paths in the copied core dump will be updated to use the new paths. RPATHs of any library/executable files will be changed to `$ORIGIN`. The core dump file will be named `<output-dir>/core`.
- `<output-dir>`: Where files should be copied to.

# Why

Sometimes you might want to copy a core dump file to another machine, and debug it there. For example, if your program crashed on a remote machine, or in CI.

It is not enough to just copy the core dump file and the main binary, you also need to copy all the shared libraries and also maintain the directory structure, and set a prefix in gdb so it can find them. This program does all of that for you, automatically.

# Caveat

This program is not fool proof. Since it mangles with the executable files, it is possible that it can do something wrong and break them. Especially if changing the RPATH changed offsets of data inside the executable. Report a bug if this doesn't work.
