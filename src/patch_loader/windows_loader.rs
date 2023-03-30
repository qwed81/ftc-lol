use winapi::um::handleapi;
use winapi::um::memoryapi;
use winapi::um::processthreadsapi;
use winapi::um::errhandlingapi;
use winapi::um::tlhelp32::TH32CS_SNAPTHREAD;
use winapi::um::tlhelp32::THREADENTRY32;
use winapi::um::psapi;
use winapi::um::winbase;
use winapi::um::tlhelp32;
use winapi::um::winnt::THREAD_ALL_ACCESS;
use winapi::um::winnt::WOW64_CONTEXT;
use winapi::um::winnt::WOW64_CONTEXT_FULL;
use winapi::um::winnt::{
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_QUERY_INFORMATION, MEM_RESERVE,
    MEM_COMMIT, PAGE_NOACCESS, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ
};

use winapi::ctypes::c_void;
use std::mem::MaybeUninit;
use std::ptr;
use std::mem;
use std::thread;
use std::time::Duration;
use std::collections::HashSet;
use std::time::Instant;

use super::{ExPtr, ExLen, MemProt, ElfOff};

pub struct Loader {
    pid: u32,
    h_proc: *mut c_void,
    reserved: Option<ExPtr>,
}

#[repr(align(16))]
struct AlignedContext(WOW64_CONTEXT);

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PatchContext {
    _context: u32,
    ret_addr: ExPtr,
    restore_esp: u32,
    restore_ebp: u32
}

#[derive(Debug, Clone, Copy)]
struct SymbolOffsetList {
    context_addr: ElfOff,
    start_addr: ElfOff,
}

const MAX_PROCESS_FILE_NAME_LEN: usize = 1_000;
const MAX_PROCESS_ITER: usize = 10_000;
const PROCESS_POLL_DURATION: Duration = Duration::from_millis(10);
const REQUIRED_PROCESS_PERMS: u32 = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;

const RESERVE_ADDR: ExPtr = 0x4020_0000;

impl Loader {

    fn get_offset_ptr(&self, offset: ExPtr) -> ElfOff {
        assert!(self.reserved.is_some());
        let base = self.reserved.unwrap();
        base + offset
    }

    // returns the handle of the process if it has that name, otherwise it returns None
    fn process_is_named(pid: u32, expected_file_name: &[u8]) -> Option<*mut c_void> {
        assert!(expected_file_name.len() <= MAX_PROCESS_FILE_NAME_LEN);
        assert!(expected_file_name.len() > 0);
        
        let process_handle = unsafe {
            processthreadsapi::OpenProcess(REQUIRED_PROCESS_PERMS, 0, pid)
        };

        if process_handle.is_null() {
            return None;
        }
        
        let file_name = unsafe {
            let mut name_buf: MaybeUninit<[u8; MAX_PROCESS_FILE_NAME_LEN]> = MaybeUninit::uninit();
            let name_buf_ptr = name_buf.assume_init_mut().as_mut_ptr() as *mut i8;
            let amt_copied = psapi::GetModuleFileNameExA(process_handle, ptr::null_mut(), name_buf_ptr,
                MAX_PROCESS_FILE_NAME_LEN as u32) as usize;
            &name_buf.assume_init()[0..amt_copied]
        };

        // println!("new process path queried: {}", String::from_utf8_lossy(file_name));
        if file_name == expected_file_name { 
            Some(process_handle) 
        } else {
            // not much to do if this fails, just leak if its still open ig
            unsafe { handleapi::CloseHandle(process_handle) };
            None 
        }
    }

    pub fn wait_spawn(process_file_name: &[u8], max_wait: Duration) -> Result<Loader, ()> {
        let start_time = Instant::now();

        let mut buffer = [0; MAX_PROCESS_ITER];
        let mut amt_returned = 0;

        let mut valid_pids = HashSet::new();
        let mut swap_set = HashSet::new();
        println!("waiting for process: \"{}\"", String::from_utf8_lossy(process_file_name));

        let (pid, handle) = 'outer: loop {
            let result = unsafe {
                psapi::EnumProcesses(buffer.as_mut_ptr(), buffer.len() as u32, &mut amt_returned)
            };

            if result == 0 {
                let err = unsafe { errhandlingapi::GetLastError() };
                println!("could not enumerate processes, error: {}", err);
                return Err(());
            }

            for i in 0..(amt_returned as usize) {
                let pid = buffer[i];
                swap_set.insert(pid);

                // it has already been looked up, and does not have that name
                if valid_pids.contains(&pid) {
                    continue;
                }

                if let Some(handle) = Loader::process_is_named(pid, process_file_name) {
                    break 'outer (pid, handle);
                }
            }
            
            valid_pids.clear();
            mem::swap(&mut valid_pids, &mut swap_set);

            if Instant::now() > start_time + max_wait {
                return Err(())
            }

            thread::sleep(PROCESS_POLL_DURATION);
        };

        Ok(Loader { pid, h_proc: handle, reserved: None })
    }

    pub fn from_pid(pid: u32) -> Result<Loader, ()> {
        let h_proc = unsafe {
            processthreadsapi::OpenProcess(REQUIRED_PROCESS_PERMS, 0, pid)
        };

        if h_proc.is_null() {
            return Err(());
        }

        Ok(Loader {
            pid,
            h_proc,
            reserved: None 
        })
    }


    pub fn reserve_mem(&mut self, len: ExLen) -> Result<(), ()> {
        assert!(self.reserved.is_none());

        // make sure that it is ok to allocate this memory, and it will not be taken up by anyone
        // else. If not all the segments map to an actual page, it is ok because it will not
        // take any physical memory
        let reserve = RESERVE_ADDR as *mut c_void;
        let alloc = unsafe {
            memoryapi::VirtualAllocEx(self.h_proc, reserve,
                len as usize, MEM_RESERVE, PAGE_NOACCESS)
        };

        if alloc.is_null() {
            let err = unsafe { errhandlingapi::GetLastError() };
            println!("could not reserve memory, error: {}", err);
            return Err(());
        }

        // make sure it can fit in the 32 bit pointer, if it can then that mem is
        // successfully reserved
        self.reserved = Some(match (alloc as u64).try_into() {
            Ok(reserved) => reserved,
            Err(_) => return Err(())
        });
        
        Ok(())
    }

    pub fn map_segment(&self, offset: ElfOff, len: ExLen) -> Result<(), ()> {
        let actual_addr = self.get_offset_ptr(offset) as *mut c_void;
        println!("map addr: {:x?} len: {}", actual_addr, len);

        let alloc = unsafe {
            memoryapi::VirtualAllocEx(self.h_proc,actual_addr,
                len as usize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        };

        if alloc.is_null() {
            let err = unsafe { errhandlingapi::GetLastError() }; 
            println!("could not map segment, error: {}", err);
            return Err(());
        }

        Ok(())
    }

    pub fn mem_write(&self, offset: ElfOff, src: &[u8]) -> Result<(), ()> {
        let actual_addr = self.get_offset_ptr(offset);
        self.mem_write_direct(actual_addr, src)
    }

    fn mem_write_direct(&self, addr: ExPtr, src: &[u8]) -> Result<(), ()> {
        println!("mem write to addr: {:x?} len: {}", addr, src.len());

        let result = unsafe {
            memoryapi::WriteProcessMemory(self.h_proc, addr as *mut c_void,
                src.as_ptr() as *const c_void, src.len(), ptr::null_mut())
        };
        
        if result == 0 {
            let err = unsafe { errhandlingapi::GetLastError() };
            println!("could not write memory, error is: {}", err);
            return Err(());
        }

        Ok(())
    }

    pub(super) fn mem_protect(&self, offset: ElfOff, len: ExLen, prot: MemProt) -> Result<(), ()> {
        let actual_addr = self.get_offset_ptr(offset);
        self.mem_protect_direct(actual_addr, len, prot)
    }

    fn mem_protect_direct(&self, addr: ExPtr, len: ExLen, prot: MemProt) -> Result<(), ()> {
        println!("mem protect at addr: {:x?} len: {} prot: {:?}", addr, len, prot);
        let prot = match prot {
            MemProt::R => PAGE_READONLY,
            MemProt::RW => PAGE_READWRITE,
            MemProt::RX => PAGE_EXECUTE_READ,
            MemProt::RWX => PAGE_EXECUTE_READWRITE
        }; 

        let mut old_prot = 0;
        let result = unsafe {
            memoryapi::VirtualProtectEx(self.h_proc, addr as *mut c_void,
                len as usize, prot, &mut old_prot)
        };

        if result == 0 {
            let err = unsafe { errhandlingapi::GetLastError() };
            println!("could not protect memory, error is: {}", err);
            return Err(());
        }

        Ok(())
    }

    fn suspend_thread(thread_handle: *mut c_void) -> Result<(), ()> {
        let suspend_result = unsafe {
            processthreadsapi::SuspendThread(thread_handle)
        };
        if suspend_result == 0xFFFFFFFF {
            let err = unsafe { errhandlingapi::GetLastError() };
            println!("thread could not suspend, error is: {}", err);
            return Err(());
        }  

        Ok(())
    }

    fn resume_thread(thread_handle: *mut c_void) -> Result<(), ()> {
        let resume_result = unsafe {
            processthreadsapi::ResumeThread(thread_handle)
        };

        if resume_result == 0xFFFFFFFF {
            let err = unsafe { errhandlingapi::GetLastError() };
            println!("thread could not resume, error is: {}", err);
            return Err(());
        }  

        Ok(())
    }
    
    fn open_victim_thread(&self) -> Result<*mut c_void, ()> {
        let snapshot = unsafe {
            tlhelp32::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
        };

        if snapshot as isize == -1 {
            let err = unsafe { errhandlingapi::GetLastError() };
            println!("could not take thread snapshot, err: {}", err);
            return Err(());
        }

        let mut entry: THREADENTRY32 = unsafe { mem::zeroed() };
        entry.dwSize = mem::size_of::<THREADENTRY32>() as u32;
        let thread_id = loop {
            let thread = unsafe {
                tlhelp32::Thread32Next(snapshot, &mut entry)
            };

            if entry.th32OwnerProcessID == self.pid {
                break entry.th32ThreadID;
            }

            if thread == 0 {
                let err = unsafe { errhandlingapi::GetLastError() };
                println!("could not get thread info, err: {}", err);
                return Err(());
            }
        };

        println!("opening victim thread: {:x}", thread_id);
        let thread_handle = unsafe {
            processthreadsapi::OpenThread(THREAD_ALL_ACCESS, 0, thread_id)
        };

        if thread_handle.is_null() {
            let err = unsafe { errhandlingapi::GetLastError() };
            println!("could not open thread, err: {}", err);
            return Err(());
        }

        Ok(thread_handle)
    }

    fn change_thread_state(&self, thread_handle: *mut c_void, address_list: SymbolOffsetList) -> Result<(), ()> {
        let mut context: AlignedContext = unsafe { mem::zeroed() };
        context.0.ContextFlags = WOW64_CONTEXT_FULL;
        let context_result = unsafe {
            winbase::Wow64GetThreadContext(thread_handle, &mut context.0)
        };
        
        if context_result == 0 {
            let err = unsafe { errhandlingapi::GetLastError() };
            println!("could not get thread context, error is: {}", err);
            return Err(());
        }

        // set the context so it can restore after executing
        let patch_context = PatchContext {
            _context: 0,
            ret_addr: context.0.Eip,
            restore_ebp: context.0.Ebp,
            restore_esp: context.0.Esp
        };

        println!("return to addr: {:x}", patch_context.ret_addr);

        let context_buf = unsafe { mem::transmute::<PatchContext, [u8; 16]>(patch_context) };
        self.mem_write_direct(address_list.context_addr, &context_buf)?;

        const STACK_ADDR: u32 = 0x4500_0000;
        const STACK_SIZE: u32 = 4096 * 16;
        // allocate a new stack so it does not touch the other stack
        let alloc = unsafe {
            memoryapi::VirtualAllocEx(self.h_proc, STACK_ADDR as *mut c_void,
                STACK_SIZE as usize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        };

        if alloc.is_null() {
            let err = unsafe { errhandlingapi::GetLastError() }; 
            println!("could allocate stack, error: {}", err);
            return Err(());
        }

        // stack grows down
        context.0.Ebp = STACK_ADDR + STACK_SIZE;
        context.0.Esp = STACK_ADDR + STACK_SIZE;

        // change instruction it starts at
        context.0.Eip = address_list.start_addr;

        let context_result = unsafe {
            winbase::Wow64SetThreadContext(thread_handle, &mut context.0)
        };

        if context_result == 0 {
            let err = unsafe { errhandlingapi::GetLastError() };
            println!("could not set thread context, error is: {}", err);
            return Err(());
        }

        Ok(())
    }

    pub fn initialize_patch(self, resolve_symbol_offset: impl Fn(&'static str) -> ElfOff) -> Result<(), ()> {
        println!("initializing patch");

        let thread_handle = self.open_victim_thread()?;
        Loader::suspend_thread(thread_handle)?;

        println!("resolving symbols");

        // get the actual pointer of a symbol
        let resolve = |name: &'static str| -> ExPtr {
            let offset = resolve_symbol_offset(name);
            self.get_offset_ptr(offset)
        };

        let address_list = SymbolOffsetList {
            context_addr: resolve("_context"),
            start_addr: resolve("_start"),
        };

        self.change_thread_state(thread_handle, address_list)?;

        Loader::resume_thread(thread_handle)?;

        Ok(())
    }

}

