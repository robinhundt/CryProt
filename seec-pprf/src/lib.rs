use seec_core::Block;

pub struct RegularPprfSender {
    conf: PprfConfig,
    base_ots: Vec<[Block; 2]>
}

pub struct RegularPprfReceiver {
    conf: PprfConfig,
    base_ots: Vec<Block>
}

impl RegularPprfSender {
    pub fn new_with_conf(conf: PprfConfig, base_ots: Vec<[Block; 2]>) -> Self {
        assert_eq!(conf.base_ot_count(), base_ots.len());
        Self {
            conf,
            base_ots,
        }
    }

    
}




pub struct PprfConfig {
    pnt_count: usize,
    domain: usize,
    depth: usize,
}

impl PprfConfig {
    pub fn new(domain: usize, pnt_count: usize) -> Self {
        let depth = log2_ceil(domain) as usize;
        Self {
            pnt_count,
            domain,
            depth,
        }
    }

    pub fn base_ot_count(&self) -> usize {
        self.depth * self.pnt_count
    }

    pub fn pnt_count(&self) -> usize {
        self.pnt_count
    }

    pub fn domain(&self) -> usize {
        self.domain
    }

    pub fn depth(&self) -> usize {
        self.depth
    }
}

fn log2_ceil(val: usize) -> usize {
    let log2 = val.ilog2();
    if val > (1 << log2) {
        (log2 + 1) as usize
    } else {
        log2 as usize
    }
}
