#[derive(Clone, Debug)]
pub struct RegFile {
    pub int_regs: Vec<i64>,
    pub cnt: u32,
}

impl RegFile {
    pub fn new(reg_file_size: usize) -> Self {
        let int_regs = vec![0; reg_file_size];
        let cnt = 0;
        RegFile { int_regs, cnt }
    }
}

pub fn init_regs(regs_num: usize) -> RegFile {
    let mut regs = RegFile::new(regs_num);
    for i in 0..regs_num {
        let mul = i as u8;
        regs.int_regs[i] = i64::from_le_bytes([
            1 * mul,
            2 * mul,
            3 * mul,
            4 * mul,
            5 * mul,
            6 * mul,
            7 * mul,
            8 * mul,
        ]);
    }
    regs
}