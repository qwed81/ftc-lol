pub mod patch_loader {
    
    pub mod load;

    #[cfg(target_os="windows")]
    #[cfg(target_arch="x86_64")]
    mod windows_loader;


    #[cfg(target_os="windows")]
    #[cfg(target_arch="x86_64")]
    pub use windows_loader::WindowsLoader as Loader;

    pub type ExPtr = u32;
    pub type ExLen = u32;

    #[derive(Debug, Clone, Copy)]
    pub enum MemProt {
        R, RW, RX, RWX 
    }  

}

