use super::LoadError;
use std::thread;
use std::time::Duration;

pub struct PatchLoader;

// not actually implemented yet, plans on doing it some time in the future
// but for now must just match windows loader interface to be able to compile
// for linux targets
impl PatchLoader {
    pub fn wait_can_patch(_name: &[u8]) -> Result<PatchLoader, LoadError> {
        // just loop infinitely
        loop {
            thread::sleep(Duration::from_secs(100));
        }
    }

    pub fn freeze_process(&mut self) -> Result<(), LoadError> {
        todo!();
    }

    pub fn wait_process_closed(&self) -> Result<(), LoadError> {
        todo!();
    }

    pub fn load_and_resume(
        &mut self,
        _elf_file: &[u8],
        _cwd: &[u8],
        _segment_table: &[u8],
    ) -> Result<(), LoadError> {
        todo!();
    }

    pub fn resume_without_load(&mut self) -> Result<(), LoadError> {
        todo!();
    }
}
