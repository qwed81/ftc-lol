use winapi::um::errhandlingapi;
use winapi::um::handleapi;
use winapi::um::libloaderapi;
use winapi::um::memoryapi;
use winapi::um::processthreadsapi;
use winapi::um::psapi;
use winapi::um::tlhelp32;
use winapi::um::tlhelp32::TH32CS_SNAPTHREAD;
use winapi::um::tlhelp32::THREADENTRY32;
use winapi::um::winnt::CONTEXT;
use winapi::um::winnt::CONTEXT_FULL;
use winapi::um::winnt::THREAD_ALL_ACCESS;
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS,
    PAGE_READONLY, PAGE_READWRITE, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
};

use super::LoadError;
use std::collections::HashSet;
use std::ffi::CString;
use std::mem;
use std::mem::MaybeUninit;
use std::ptr;
use std::slice;
use std::time::{Duration, Instant};
use winapi::ctypes::c_void;
use std::thread;

use goblin::elf::{Elf, ProgramHeader};
use goblin::elf64::program_header::PT_LOAD;

use super::elf_util::{self, LoadRange};
use super::ElfLen;
use super::{ElfOff, ExLen, ExPtr, MemProt};

const MAX_PROCESS_FILE_NAME_LEN: usize = 1_000;
const MAX_PROCESS_ITER: usize = 10_000;
const MAX_MODULES: usize = 1000;

// the amount of modules that need to be loaded before the thread is suspended and we apply hooks
const PATCH_LOAD_MOD_AMT_THRESHOLD: usize = 5;

const PROCESS_POLL_DURATION: Duration = Duration::from_millis(10);
const MOD_POLL_DURATION: Duration = Duration::from_millis(1);
const TIME_BEFORE_MOD_POLL_FAIL: Duration = Duration::from_secs(20);

const REQUIRED_PROCESS_PERMS: u32 =
    PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;

// randomly picked numbers, maybe need to be changed in the future?
// will work as long as MODULE_OFFSET fits within i32
const STACK_OFFSET: i64 = 0x0030_0000;
const STACK_LEN: ExLen = 10 * 4096;
const SEG_TABLE_OFFSET: i64 = 0x0050_0000;

#[derive(Debug, Clone, Copy)]
struct ThreadContextArgs {
    ret_addr_addr: ExPtr,
    restore_esp_addr: ExPtr,
    restore_ebp_addr: ExPtr,
    start_addr: ExPtr,
    new_esp: ExPtr,
}

pub struct PatchLoader {
    proc: Process,
    thread_handle: Option<*mut c_void>,
}

impl PatchLoader {
    pub fn wait_can_patch(process_file_name: &[u8]) -> Result<PatchLoader, LoadError> {
        let proc = wait_process_created(process_file_name)?;
        proc.wait_can_patch()?;

        Ok(PatchLoader {
            proc,
            thread_handle: None,
        })
    }

    pub fn wait_process_closed(&self) -> Result<(), LoadError> {
        wait_closed(self.proc.pid)
    }

    pub fn freeze_process(&mut self) -> Result<(), LoadError> {
        let thread_handle = self.proc.open_victim_thread()?;
        suspend_thread(thread_handle)?;

        self.thread_handle = Some(thread_handle);
        Ok(())
    }

    pub fn resume_without_load(&mut self) -> Result<(), LoadError> {
        resume_thread(self.thread_handle.unwrap())
    }

    pub fn load_and_resume(
        &mut self,
        elf_file: &[u8],
        cwd: &[u8],
        segment_table: &[u8],
    ) -> Result<(), LoadError> {
        assert!(self.thread_handle.is_some());
        assert!(cwd.len() < 1024);

        let thread_handle = self.thread_handle.unwrap();

        let elf = Elf::parse(&elf_file).unwrap();
        let LoadRange { elf_start, elf_end } = elf_util::get_load_range(&elf.program_headers);

        let elf_len = elf_end - elf_start;

        // we need to load in the address of all of the __load_ function addresses,
        // so it can call the functions that it needs
        let kernel32_handle = unsafe {
            let kernel32_text = "kernel32\0".as_ptr() as *const i8;
            libloaderapi::GetModuleHandleA(kernel32_text)
        };

        if kernel32_handle == ptr::null_mut() {
            panic!("Could not find kernel32");
        }

        fn offset(p: ExPtr, o: i64) -> ExPtr {
            (p as i128 + o as i128) as ExPtr
        }

        // this is tricky because it has to be within a 32 bit pointer of kernel32, because
        // it can then utilize 32bit relative jumps
        let mut load_addr = kernel32_handle as ExPtr & 0xFFFFFFFF_80000000;
        while let Err(_) = self.proc.reserve_mem(load_addr, elf_len as ExLen) {
            load_addr += 0x1000000;
        }

        // load elf sections
        let mut zero_buffer = Vec::new();
        for header in &elf.program_headers {
            if header.p_type != PT_LOAD {
                continue;
            }

            load_segment(
                elf_file,
                header,
                &mut self.proc,
                elf_start,
                &mut zero_buffer,
            )?;
        }

        let stack_addr = offset(load_addr, STACK_OFFSET);
        self.proc.allocate_mem(stack_addr, STACK_LEN)?;

        let seg_table_addr = offset(load_addr, SEG_TABLE_OFFSET);
        self.proc
            .allocate_mem(seg_table_addr, segment_table.len().try_into().unwrap())?;
        self.proc.mem_write_direct(seg_table_addr, segment_table)?;

        let resolve = |name: &str| -> ExPtr {
            let offset = elf_util::get_sym_offset(&elf, name);
            match offset {
                Some(offset) => self.proc.get_offset_ptr(offset),
                None => panic!("The symbol {} does not exist in the binary", name),
            }
        };

        let seg_tab_addr_addr = resolve("arg_seg_table_addr");
        self.proc
            .mem_write_direct(seg_tab_addr_addr, &seg_table_addr.to_le_bytes())?;

        let path_root_buf_addr = resolve("path_root_buf");
        self.proc.mem_write_direct(path_root_buf_addr, cwd)?;

        // constants defined in boostrap.s of the
        let thread_args = ThreadContextArgs {
            ret_addr_addr: resolve("ret_addr"),
            restore_esp_addr: resolve("restore_esp"),
            restore_ebp_addr: resolve("restore_ebp"),
            start_addr: resolve("_start"),
            // the stack grows down, so we have to start at the end of the
            // memory segment
            new_esp: stack_addr + STACK_LEN,
        };

        self.proc
            .change_thread_context(thread_handle, &thread_args)?;

        for (func_name, elf_off) in elf_util::get_load_symbols(&elf) {
            let c_func_name = CString::new(func_name).unwrap();
            let addr =
                unsafe { libloaderapi::GetProcAddress(kernel32_handle, c_func_name.as_ptr()) };

            if addr.is_null() {
                return Err(LoadError {
                    message: format!("could not get address for function: {}", func_name),
                    code: None
                });
            }

            // write the actual pointer into their memory
            self.proc
                .mem_write(elf_off, &(addr as ExPtr).to_ne_bytes())?;
        }

        resume_thread(thread_handle)?;
        Ok(())
    }
}

impl Drop for PatchLoader {
    fn drop(&mut self) {
        if let Some(handle) = self.thread_handle {
            unsafe { handleapi::CloseHandle(handle) };
        }
    }
}

#[repr(align(16))]
struct AlignedContext(CONTEXT);

struct Process {
    pid: u32,
    process_handle: *mut c_void,
    reserved: Option<ExPtr>,
}

impl Process {
    fn get_offset_ptr(&self, offset: ElfOff) -> ExPtr {
        assert!(self.reserved.is_some());
        let base = self.reserved.unwrap();
        base + offset as ExPtr
    }

    fn wait_can_patch(&self) -> Result<(), LoadError> {
        let mut modules = [ptr::null_mut(); MAX_MODULES];
        let start = Instant::now();
        loop {
            let mut amt_needed = 0;
            let result = unsafe {
                psapi::EnumProcessModules(
                    self.process_handle,
                    modules.as_mut_ptr(),
                    modules.len() as u32,
                    &mut amt_needed,
                )
            };

            // when it is loading and there are no modules, it is expected that this
            // call fails
            if result == 0 {
                let err = unsafe { errhandlingapi::GetLastError() };
                if err != 299 {
                    return Err(LoadError {
                        message: format!("error while enumerating modules"),
                        code: Some(err)
                    });
                }

                thread::sleep(MOD_POLL_DURATION);
                continue;
            }

            let mod_amt = amt_needed as usize / mem::size_of::<*mut c_void>();

            // it is done loading enough for us to suspend and patch it
            if mod_amt >= PATCH_LOAD_MOD_AMT_THRESHOLD {
                return Ok(());
            }

            if Instant::now() - start > TIME_BEFORE_MOD_POLL_FAIL {
                return Err(LoadError {
                    message: format!("waiting for patchable timed out"),
                    code: None
                });
            }

            thread::sleep(MOD_POLL_DURATION);
        }
    }

    fn reserve_mem(&mut self, start: ExPtr, len: ExLen) -> Result<(), LoadError> {
        assert!(self.reserved.is_none());

        // make sure that it is ok to allocate this memory, and it will not be taken up by anyone
        // else. If not all the segments map to an actual page, it is ok because it will not
        // take any physical memory
        let reserve = start as *mut c_void;
        let alloc = unsafe {
            memoryapi::VirtualAllocEx(
                self.process_handle,
                reserve,
                len as usize,
                MEM_RESERVE,
                PAGE_NOACCESS,
            )
        };

        if alloc.is_null() {
            let err = unsafe { errhandlingapi::GetLastError() };
            return Err(LoadError {
                message: format!("could not reserve memory at: {:x}, len: {}", start, len),
                code: Some(err)
            });
        }

        self.reserved = Some(alloc as ExPtr);
        Ok(())
    }

    fn map_segment(&self, offset: ElfOff, len: ElfLen) -> Result<(), LoadError> {
        let actual_addr = self.get_offset_ptr(offset) as *mut c_void;
        let alloc = unsafe {
            memoryapi::VirtualAllocEx(
                self.process_handle,
                actual_addr,
                len as usize,
                MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            )
        };

        if alloc.is_null() {
            let err = unsafe { errhandlingapi::GetLastError() };
            return Err(LoadError {
                message: format!("could not map segment, addr: {:x}", actual_addr as ExPtr),
                code: Some(err)
            });
        }

        Ok(())
    }

    fn mem_write(&self, offset: ElfOff, src: &[u8]) -> Result<(), LoadError> {
        let actual_addr = self.get_offset_ptr(offset);
        self.mem_write_direct(actual_addr, src)
    }

    fn mem_write_direct(&self, addr: ExPtr, src: &[u8]) -> Result<(), LoadError> {
        let result = unsafe {
            memoryapi::WriteProcessMemory(
                self.process_handle,
                addr as *mut c_void,
                src.as_ptr() as *const c_void,
                src.len(),
                ptr::null_mut(),
            )
        };

        if result == 0 {
            let err = unsafe { errhandlingapi::GetLastError() };
            return Err(LoadError {
                message: format!("could not write memory, addr: {:x}", addr),
                code: Some(err)
            });
        }

        Ok(())
    }

    fn mem_protect(&self, offset: ElfOff, len: ElfLen, prot: MemProt) -> Result<(), LoadError> {
        let actual_addr = self.get_offset_ptr(offset);
        self.mem_protect_direct(actual_addr, len as ExLen, prot)
    }

    fn mem_protect_direct(&self, addr: ExPtr, len: ExLen, prot: MemProt) -> Result<(), LoadError> {
        let prot = match prot {
            MemProt::R => PAGE_READONLY,
            MemProt::RW => PAGE_READWRITE,
            MemProt::RX => PAGE_EXECUTE_READ,
            MemProt::RWX => PAGE_EXECUTE_READWRITE,
        };

        let mut old_prot = 0;
        let result = unsafe {
            memoryapi::VirtualProtectEx(
                self.process_handle,
                addr as *mut c_void,
                len as usize,
                prot,
                &mut old_prot,
            )
        };

        if result == 0 {
            let err = unsafe { errhandlingapi::GetLastError() };
            return Err(LoadError {
                message: format!("could not protect memory, addr: {:x}", addr),
                code: Some(err)
            });
        }

        Ok(())
    }

    fn open_victim_thread(&self) -> Result<*mut c_void, LoadError> {
        let snapshot = unsafe { tlhelp32::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid) };

        if snapshot as isize == -1 {
            let err = unsafe { errhandlingapi::GetLastError() };
            return Err(LoadError {
                message: format!("could not take thread snapshot"),
                code: Some(err)
            });
        }

        let mut entry: THREADENTRY32 = unsafe { mem::zeroed() };
        entry.dwSize = mem::size_of::<THREADENTRY32>() as u32;
        let thread_id = loop {
            let thread = unsafe { tlhelp32::Thread32Next(snapshot, &mut entry) };

            if entry.th32OwnerProcessID == self.pid {
                break entry.th32ThreadID;
            }

            if thread == 0 {
                let err = unsafe { errhandlingapi::GetLastError() };
                return Err(LoadError {
                    message: format!("could not get thread info"),
                    code: Some(err)
                });
            }
        };

        let thread_handle =
            unsafe { processthreadsapi::OpenThread(THREAD_ALL_ACCESS, 0, thread_id) };

        if thread_handle.is_null() {
            let err = unsafe { errhandlingapi::GetLastError() };
            return Err(LoadError {
                message: format!("could not open thread, id: {:x}", thread_id),
                code: Some(err)
            });
        }

        Ok(thread_handle)
    }

    fn allocate_mem(&self, addr: ExPtr, len: ExLen) -> Result<(), LoadError> {
        let alloc = unsafe {
            memoryapi::VirtualAllocEx(
                self.process_handle,
                addr as *mut c_void,
                len as usize,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };

        if alloc.is_null() {
            let err = unsafe { errhandlingapi::GetLastError() };
            return Err(LoadError {
                message: format!("could not allocate mem, addr: {:x}", addr),
                code: Some(err)
            });
        }

        Ok(())
    }

    fn change_thread_context(
        &self,
        thread_handle: *mut c_void,
        args: &ThreadContextArgs,
    ) -> Result<(), LoadError> {
        let mut context: AlignedContext = unsafe { mem::zeroed() };
        context.0.ContextFlags = CONTEXT_FULL;
        let context_result =
            unsafe { processthreadsapi::GetThreadContext(thread_handle, &mut context.0) };

        if context_result == 0 {
            let err = unsafe { errhandlingapi::GetLastError() };
            return Err(LoadError { 
                message: format!("could not get thread context"),
                code: Some(err) 
            });
        }

        // load the old values into memory so they can be restored
        self.mem_write_direct(args.ret_addr_addr, &context.0.Rip.to_le_bytes())?;
        self.mem_write_direct(args.restore_ebp_addr, &context.0.Rbp.to_le_bytes())?;
        self.mem_write_direct(args.restore_esp_addr, &context.0.Rsp.to_le_bytes())?;

        // set the new values
        context.0.Rbp = args.new_esp;
        context.0.Rsp = args.new_esp;
        context.0.Rip = args.start_addr;

        let context_result =
            unsafe { processthreadsapi::SetThreadContext(thread_handle, &mut context.0) };

        if context_result == 0 {
            let err = unsafe { errhandlingapi::GetLastError() };
            return Err(LoadError { 
                message: format!("could not set thread context"),
                code: Some(err) 
            });
        }

        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe { handleapi::CloseHandle(self.process_handle) };
    }
}

fn load_segment(
    file: &[u8],
    header: &ProgramHeader,
    process: &mut Process,
    elf_start: ElfOff,
    zero_buffer: &mut Vec<u64>,
) -> Result<(), LoadError> {
    // the file memory is always less than vm memory range. The
    // difference in the range needs to be zeroed out, as specified by ELF file
    let f_range = header.file_range();
    let m_range = header.vm_range();

    let copy_len: ElfLen = f_range.len().try_into().unwrap();
    let total_len = m_range.len().try_into().unwrap();
    let vm_offset = (m_range.start - elf_start as usize).try_into().unwrap();
    process.map_segment(vm_offset, total_len)?;

    // write the actual data from the file into memory
    process.mem_write(vm_offset, &file[f_range])?;

    let left_over_len = (total_len - copy_len) as usize;

    // need to copy over a bunch of zeros to fill out the
    // gap in memory if the vm size is greater than file size
    if left_over_len > 0 {
        while zero_buffer.len() < left_over_len / 4 + 1 {
            zero_buffer.push(0u64);
        }

        let u8_ptr = zero_buffer.as_ptr() as *const u8;
        let slice = unsafe { slice::from_raw_parts(u8_ptr, left_over_len) };

        process.mem_write(vm_offset + copy_len, slice)?;
    }

    // enable the protections requested
    let prot = elf_util::get_protection(header);
    process.mem_protect(vm_offset, total_len, prot)
}

fn suspend_thread(thread_handle: *mut c_void) -> Result<(), LoadError> {
    let suspend_result = unsafe { processthreadsapi::SuspendThread(thread_handle) };
    if suspend_result == 0xFFFFFFFF {
        let err = unsafe { errhandlingapi::GetLastError() };
        return Err(LoadError {
            message: format!("could not suspend thread"),
            code: Some(err)
        });
    }

    Ok(())
}

fn resume_thread(thread_handle: *mut c_void) -> Result<(), LoadError> {
    let resume_result = unsafe { processthreadsapi::ResumeThread(thread_handle) };

    if resume_result == 0xFFFFFFFF {
        let err = unsafe { errhandlingapi::GetLastError() };
        return Err(LoadError {
            message: format!("could not resume thread"),
            code: Some(err)
        });
    }

    Ok(())
}

fn wait_closed(pid: u32) -> Result<(), LoadError> {
    let mut buf = Vec::with_capacity(MAX_PROCESS_ITER);
    for _ in 0..MAX_PROCESS_ITER {
        buf.push(0);
    }

    loop {
        let mut size_needed = 0;
        let result =
            unsafe { psapi::EnumProcesses(buf.as_mut_ptr(), buf.len() as u32, &mut size_needed) };

        if result == 0 {
            let err = unsafe { errhandlingapi::GetLastError() };
            return Err(LoadError {
                message: format!("could not enumerate processes"),
                code: Some(err)
            });
        }

        let amt_returned = size_needed as usize / mem::size_of::<u32>();
        let mut should_break = true;
        for &x in &buf[0..amt_returned] {
            if x == pid {
                should_break = false;
                break;
            }
        }

        if should_break {
            break;
        }

        thread::sleep(PROCESS_POLL_DURATION);
    }

    Ok(())
}

fn wait_process_created(process_file_name: &[u8]) -> Result<Process, LoadError> {
    // we can use the fact the EnumProcesses returns items in the same
    // order they were before if nothing changed to just to an arr comparison
    // which is super cheap compared to other methods
    // these are heap allocated because the future would be massive if they were
    // stack allocated
    let mut buf1 = Vec::with_capacity(MAX_PROCESS_ITER);
    let mut buf2 = Vec::with_capacity(MAX_PROCESS_ITER);
    for _ in 0..MAX_PROCESS_ITER {
        buf1.push(0);
        buf2.push(0);
    }

    // allows us to swap the reference so we don't have to copy
    // between buffers
    let mut buf_ref = &mut buf1;
    let mut old_ref = &mut buf2;

    let mut size_needed = 0;
    let mut old_returned = 0;
    let mut amt_returned;

    // in the case the arrays don't equal, this holds the previous values
    // so we can lookup items fast and determine which items need to be added
    let mut old_pids = HashSet::new();
    let (pid, handle) = 'outer: loop {
        let result = unsafe {
            psapi::EnumProcesses(buf_ref.as_mut_ptr(), buf_ref.len() as u32, &mut size_needed)
        };

        if result == 0 {
            let err = unsafe { errhandlingapi::GetLastError() };
            return Err(LoadError {
                message: format!("could not enumerate processes"),
                code: Some(err)
            });
        }

        amt_returned = size_needed as usize / mem::size_of::<u32>();

        let slice = &buf_ref[0..amt_returned];
        let old_slice = &old_ref[0..old_returned];
        // if there was a change in the pid list
        if amt_returned != old_returned || slice != old_slice {
            for &pid in slice {
                // this pid is old, so we don't need to check it
                if old_pids.contains(&pid) {
                    continue;
                }

                // if we found the process, then break out of the loop
                if let Some(handle) = process_is_named(pid, process_file_name) {
                    break 'outer (pid, handle);
                }
            }

            // set the old pids to the new pids
            old_pids.clear();
            for &pid in slice {
                old_pids.insert(pid);
            }
        }

        mem::swap(&mut buf_ref, &mut old_ref);
        old_returned = amt_returned;

        thread::sleep(PROCESS_POLL_DURATION);
    };

    Ok(Process {
        pid,
        process_handle: handle,
        reserved: None,
    })
}

// returns the handle of the process if it has that name, otherwise it returns None
fn process_is_named(pid: u32, expected_file_name: &[u8]) -> Option<*mut c_void> {
    assert!(expected_file_name.len() <= MAX_PROCESS_FILE_NAME_LEN);
    assert!(expected_file_name.len() > 0);

    let process_handle = unsafe { processthreadsapi::OpenProcess(REQUIRED_PROCESS_PERMS, 0, pid) };

    if process_handle.is_null() {
        return None;
    }

    let file_name = unsafe {
        let mut name_buf: MaybeUninit<[u8; MAX_PROCESS_FILE_NAME_LEN]> = MaybeUninit::uninit();
        let name_buf_ptr = name_buf.assume_init_mut().as_mut_ptr() as *mut i8;
        let amt_copied = psapi::GetModuleFileNameExA(
            process_handle,
            ptr::null_mut(),
            name_buf_ptr,
            MAX_PROCESS_FILE_NAME_LEN as u32,
        ) as usize;
        &name_buf.assume_init()[0..amt_copied]
    };

    if file_name == expected_file_name {
        Some(process_handle)
    } else {
        // not much to do if this fails, just leak if its still open ig
        unsafe { handleapi::CloseHandle(process_handle) };
        None
    }
}
