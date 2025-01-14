coredump-copy
=============

# Usage

```
coredump-copy <input> <output-dir>
```


- `<input>`: The core dump file to copy. This will copy the core dump file along with all the files it references. The resulting core dump will be modified to reference the new paths. The core dump file will be named `<output-dir>/core`.
- `<output-dir>`: Where files should be copied to.

# Why

Sometimes you might want to copy a core dump file to another machine, and debug it there. For example, when your program crashed on a remote machine, or in CI.

It is not enough to just copy the core dump file and the main binary, you also need to copy all the shared libraries and also maintain the directory structure, and set a prefix in gdb so it can find them. This program does all of that for you, automatically.

# Caveat

This program is not fool proof. Since it mangles with the core dump files, it is possible that it can do something wrong and break them. Report a bug if this doesn't work.
