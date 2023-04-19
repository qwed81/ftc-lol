pub struct PatchLoader;

impl PatchLoader {
    pub async fn wait_can_patch(_name: &[u8]) -> Result<PatchLoader, ()> {
        todo!();
    }

    pub fn freeze_process(&mut self) -> Result<(), ()> { 
        todo!();
    }

    pub fn load_and_resume(&mut self, _elf_file: &[u8], _cwd: &[u8], _segment_table: &[u8]) -> Result<(), ()> {
        let _ = self;
        todo!();
    }

    pub fn resume_without_load(&mut self) {
        todo!();
    }
}


