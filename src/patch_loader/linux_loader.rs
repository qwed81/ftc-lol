struct PatchLoader;

impl PatchLoader {
    pub async fn wait_can_patch(_name: &[u8]) -> Result<PatchLoader, ()> {
        todo!();
    }

    pub fn freeze_process(&mut self) -> Result<(), ()> { 
        todo!();
    }

    pub async fn load_and_resume(mut self, elf_file: &[u8], segment_table: &[u8]) -> Result<(), ()> {
        todo!();
    }
}


