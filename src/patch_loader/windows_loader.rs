use winapi::um::memoryapi;
use winapi::um::processthreadsapi;
use winapi::um::errhandlingapi;
use winapi::um::tlhelp32::TH32CS_SNAPTHREAD;
use winapi::um::tlhelp32::THREADENTRY32;
use winapi::um::winbase;
use winapi::um::tlhelp32;
use winapi::um::winnt::THREAD_ALL_ACCESS;
use winapi::um::winnt::WOW64_CONTEXT;
use winapi::um::winnt::WOW64_CONTEXT_FULL;
use winapi::um::winnt::{
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
    MEM_RESERVE, MEM_COMMIT, PAGE_NOACCESS, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ
};

use winapi::ctypes::c_void;
use std::ptr;
use std::mem;

use super::{ExPtr, ExLen, MemProt};

pub struct WindowsLoader {
    pid: u32,
    h_proc: *mut c_void,
    reserved: Option<ExPtr>,
}

#[repr(align(16))]
struct AlignedContext(WOW64_CONTEXT);

// a random address that is not taken to load the patch into
const DEFAULT_ADDRESS: ExPtr = 0x4000_0000;

impl WindowsLoader {

    fn get_offset_ptr(&self, offset: ExPtr) -> ExPtr {
        assert!(self.reserved.is_some());
        let base = self.reserved.unwrap();
        base + offset
    }

    pub fn from_pid(pid: u32) -> Result<Self, ()> {
        // get the pid
        let create_thread_perms = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;
        let mem_perms = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;
        let perms = create_thread_perms | mem_perms;

        let h_proc = unsafe {
            processthreadsapi::OpenProcess(perms, 0, pid)
        };

        if h_proc.is_null() {
            return Err(());
        }

        Ok(WindowsLoader {
            pid,
            h_proc,
            reserved: None 
        })
    }

    pub fn reserve_mem(&mut self, reserve_addr: ExPtr, len: ExLen) -> Result<(), ()> {
        assert!(self.reserved.is_none());

        println!("reserving memory, addr: {:x?} len: {}", reserve_addr, len);

        // make sure that it is ok to allocate this memory, and it will not be taken up by anyone
        // else. If not all the segments map to an actual page, it is ok because it will not
        // take any physical memory
        let reserve = reserve_addr as *mut c_void;
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

    pub fn map_segment(&self, offset: ExPtr, len: ExLen) -> Result<(), ()> {
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

    pub fn mem_write(&self, offset: ExPtr, src: &[u8]) -> Result<(), ()> {
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

    pub fn mem_protect(&self, offset: ExPtr, len: ExLen, prot: MemProt) -> Result<(), ()> {
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


    fn change_thread_state(&self, thread_handle: *mut c_void, start_addr: ExPtr, context_addr: ExPtr) -> Result<(), ()> {
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

        // change the starting and give it the address it needs to jump back to
        let remote_context = (context.0.Eip, context.0.Eax);
        let remote_context = unsafe { mem::transmute::<(u32, u32), [u8; 8]>(remote_context) };
        self.mem_write_direct(context_addr, &remote_context);

        context.0.Eip = start_addr;
        context.0.Eax = context_addr;

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

    pub fn initialize_patch(self, start_proc_offset: ExPtr, context_offset: ExPtr) -> Result<(), ()> {
        println!("initializing patch");

        let thread_handle = self.open_victim_thread()?;
        suspend_thread(thread_handle)?;

        let start_addr = self.get_offset_ptr(start_proc_offset);
        let context_addr = self.get_offset_ptr(context_offset);
        self.change_thread_state(thread_handle, start_addr, context_addr)?;

        resume_thread(thread_handle)?;

        Ok(())
    }

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

   /*
fn create_rel_jmp(instruction_pos: ExPtr, jump_to_pos: ExPtr) -> [u8; 6] {
    let mut instruction = [0xFF, 0x25, 0, 0, 0, 0];

    // calculate the jump to including the size of this instruction
    // let rip_offset: i32 = (jump_to_pos as i64 - instruction_pos as i64 - 6).try_into().unwrap();
    let rip_offset = -6;
    unsafe {
        let rest_ptr = instruction.as_mut_ptr().offset(2) as *mut i32;
        *rest_ptr = rip_offset;
    }
    
    instruction
}
    fn start_remote_thread(&mut self, start_addr: ExPtr) -> Result<(), ()> {
        println!("thread starting at addr: {:x?}", start_addr);
        let start_fn = unsafe {
            mem::transmute::<usize, Option<unsafe extern "system" fn (*mut c_void) -> u32>>(0x03D5_0000)
        };
        
        let mut thread_id = 0;
        const START_PAUSED: u32 = 4;
        let thread_handle = unsafe {
            processthreadsapi::CreateRemoteThread(self.h_proc, ptr::null_mut(), 0x2000, 
                start_fn, ptr::null_mut(), START_PAUSED, &mut thread_id)
        };

        if thread_handle.is_null() {
            let err = unsafe { errhandlingapi::GetLastError() }; 
            println!("could not create thread, error is: {}", err);
            return Err(());
        }

        println!("created thread, id is: {}", thread_id);

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

        context.0.Eip = start_addr;
        let context_result = unsafe {
            winbase::Wow64SetThreadContext(thread_handle, &mut context.0)
        };

        if context_result == 0 {
            let err = unsafe { errhandlingapi::GetLastError() };
            println!("could not set thread context, error is: {}", err);
            return Err(());
        }

        let resume_result = unsafe {
            processthreadsapi::ResumeThread(thread_handle)
        };

        if resume_result == 0xFFFFFFFF {
            let err = unsafe { errhandlingapi::GetLastError() };
            println!("thread could not resume, error is: {}", err);
            return Err(());
        }  

        std::thread::sleep(Duration::from_millis(1000));

        let mut thread_exit_code = 0;
        let exit_code_result = unsafe {
            processthreadsapi::GetExitCodeThread(thread_handle, &mut thread_exit_code)
        };

        if exit_code_result == 0 {
            let err = unsafe { errhandlingapi::GetLastError() };
            println!("could not get exit code, error is: {}", err);
            return Err(());
        }
        println!("thread exit code is: {}", thread_exit_code);

        Ok(())
    }
    */