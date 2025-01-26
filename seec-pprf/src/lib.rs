use std::{array, cmp::Ordering};

use aes::{
    cipher::{BlockCipherEncrypt, KeyInit},
    Aes128,
};
use bytemuck::{cast_slice, cast_slice_mut};
use futures::{SinkExt, StreamExt};
use ndarray::Array2;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use seec_core::{
    aes_hash::FIXED_KEY_HASH,
    aes_rng::AesRng,
    utils::{allocate_zeroed_vec, xor_inplace},
    Block, AES_PAR_BLOCKS,
};
use seec_net::Connection;
use serde::{Deserialize, Serialize};

pub struct RegularPprfSender {
    conn: Connection,
    conf: PprfConfig,
    base_ots: Array2<[Block; 2]>,
}

pub struct RegularPprfReceiver {
    conn: Connection,
    conf: PprfConfig,
    base_ots: Array2<Block>,
    base_choices: Array2<u8>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OutFormat {
    ByLeafIndex,
    ByTreeIndex,
    Interleaved,
}

pub const PARALLEL_TREES: usize = AES_PAR_BLOCKS;

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct TreeGrp {
    g: usize,
    sums: [Vec<[Block; PARALLEL_TREES]>; 2],
    last_ots: Vec<[Block; 4]>, // TOOD 4 correct???
}

impl RegularPprfSender {
    pub fn new_with_conf(conn: Connection, conf: PprfConfig, base_ots: Array2<[Block; 2]>) -> Self {
        assert_eq!(conf.base_ot_count(), base_ots.len());
        Self {
            conn,
            conf,
            base_ots,
        }
    }

    pub async fn expand(mut self, value: Block, seed: Block, out_fmt: OutFormat) -> Array2<Block> {
        let (rows, cols) = out_fmt.out_dims(&self.conf);
        let mut output = Array2::zeros([rows, cols]);
        let aes = create_fixed_aes();
        let depth = self.conf.depth();
        let pnt_count = self.conf.pnt_count();
        let domain = self.conf.domain();

        let mut rng = AesRng::from_seed(seed);
        let dd = match out_fmt {
            OutFormat::Interleaved => depth,
            _ => depth + 1,
        };

        let (mut snd, _) = self.conn.stream().await.unwrap();

        let mut tree: Vec<[Block; PARALLEL_TREES]> = allocate_zeroed_vec(2_usize.pow(dd as u32));

        for g in (0..pnt_count).step_by(PARALLEL_TREES) {
            let mut tree_grp = TreeGrp {
                g,
                ..Default::default()
            };
            let min = PARALLEL_TREES.min(pnt_count - g);
            let level: &mut [u8] = cast_slice_mut(get_level(&mut tree, 0));
            rng.fill_bytes(level);
            tree_grp.sums[0].resize(depth, Default::default());
            tree_grp.sums[1].resize(depth, Default::default());

            for d in 0..depth {
                let (lvl0, lvl1) = if out_fmt == OutFormat::Interleaved && d + 1 == depth {
                    (
                        get_level(&mut tree, d),
                        get_level_output(&mut output, g, domain),
                    )
                } else {
                    get_cons_levels(&mut tree, d)
                };

                let width = lvl1.len();
                let mut child_idx = 0;
                while child_idx < width {
                    let parent_idx = child_idx >> 1;
                    let parent = &lvl0[parent_idx];
                    for keep in 0..2 {
                        let child = &mut lvl1[child_idx];
                        let sum = &mut tree_grp.sums[keep][d];
                        aes[keep]
                            .encrypt_blocks_b2b(cast_slice(parent), cast_slice_mut(child))
                            .expect("parent and child have same len");
                        xor_inplace(child, parent);
                        xor_inplace(sum, child);
                        child_idx += 1;
                    }
                }
            }

            let mut mask_sums = |idx: usize| {
                for (d, sums) in tree_grp.sums[idx].iter_mut().take(depth - 1).enumerate() {
                    for (j, sum) in sums.iter_mut().enumerate().take(min) {
                        *sum ^= self.base_ots[(g + j, d)][idx];
                    }
                }
            };
            mask_sums(0);
            mask_sums(1);

            let d = depth - 1;
            tree_grp.last_ots.resize(min, Default::default());
            for j in 0..min {
                tree_grp.last_ots[j][0] = tree_grp.sums[0][d][j];
                tree_grp.last_ots[j][1] = tree_grp.sums[1][d][j] ^ value;
                tree_grp.last_ots[j][2] = tree_grp.sums[1][d][j];
                tree_grp.last_ots[j][3] = tree_grp.sums[0][d][j] ^ value;

                let mask_in = [
                    self.base_ots[(g + j, d)][0],
                    self.base_ots[(g + j, d)][0] ^ Block::ONES,
                    self.base_ots[(g + j, d)][1],
                    self.base_ots[(g + j, d)][1] ^ Block::ONES,
                ];
                let masks = FIXED_KEY_HASH.cr_hash_blocks(&mask_in);
                xor_inplace(&mut tree_grp.last_ots[j], &masks);
            }
            tree_grp.sums[0].truncate(depth - 1);
            tree_grp.sums[1].truncate(depth - 1);

            snd.send(tree_grp).await.unwrap();
            if out_fmt != OutFormat::Interleaved {
                todo!()
            }
        }

        output
    }
}

impl RegularPprfReceiver {
    pub fn new_with_conf(
        conn: Connection,
        conf: PprfConfig,
        base_ots: Array2<Block>,
        base_choices: Array2<u8>,
    ) -> Self {
        assert_eq!(conf.base_ot_count(), base_ots.len());
        Self {
            conn,
            conf,
            base_ots,
            base_choices,
        }
    }

    pub async fn expand(mut self, out_fmt: OutFormat) -> Array2<Block> {
        if out_fmt == OutFormat::Interleaved {
            assert_eq!(
                0,
                 self.conf.pnt_count() % PARALLEL_TREES,
                  "for OutFormat::Interleaved, conf.pnt_count() needs to be multiple of PARALLEL_TREES"
                );
        }
        let (rows, cols) = out_fmt.out_dims(&self.conf);
        // TODO not sure if can use Array2, since it is column major order
        let mut output = Array2::zeros([rows, cols]);
        let aes = create_fixed_aes();
        let points = self.get_points(OutFormat::ByLeafIndex);
        let depth = self.conf.depth();
        let pnt_count = self.conf.pnt_count();
        let domain = self.conf.domain();

        let dd = match out_fmt {
            OutFormat::Interleaved => depth,
            _ => depth + 1,
        };

        let (_, mut rx) = self.conn.stream().await.unwrap();

        let mut tree: Vec<[Block; PARALLEL_TREES]> = allocate_zeroed_vec(2_usize.pow(dd as u32));
        for g in (0..pnt_count).step_by(PARALLEL_TREES) {
            let tree_grp: TreeGrp = rx.next().await.unwrap().unwrap();
            assert_eq!(g, tree_grp.g);

            let lvl1 = get_level(&mut tree, 1);
            for i in 0..PARALLEL_TREES {
                let not_ai = self.base_choices[(i + g, 0)] as usize;
                lvl1[not_ai][i] = self.base_ots[(i + g, 0)] ^ tree_grp.sums[not_ai][0][i];
                lvl1[not_ai ^ 1][i] = Block::ZERO;
            }

            let mut my_sums = [[Block::ZERO; PARALLEL_TREES]; 2];

            for d in 1..depth {
                let (lvl0, lvl1) = if out_fmt == OutFormat::Interleaved && d + 1 == depth {
                    (
                        get_level(&mut tree, d),
                        get_level_output(&mut output, g, domain),
                    )
                } else {
                    get_cons_levels(&mut tree, d)
                };

                my_sums = [[Block::ZERO; PARALLEL_TREES]; 2];
                let width = lvl1.len();
                let mut child_idx = 0;
                while child_idx < width {
                    let parent_idx = child_idx >> 1;
                    let parent = &lvl0[parent_idx];
                    for keep in 0..2 {
                        let child = &mut lvl1[child_idx];
                        let sum = &mut my_sums[keep];
                        aes[keep]
                            .encrypt_blocks_b2b(cast_slice(parent), cast_slice_mut(child))
                            .expect("parent and child have same len");
                        xor_inplace(child, parent);
                        xor_inplace(sum, child);
                        child_idx += 1;
                    }
                }

                if d != depth - 1 {
                    for i in 0..PARALLEL_TREES {
                        let leaf_idx = points[i + g];
                        let active_child_idx = leaf_idx >> (depth - 1 - d);
                        let inactive_child_idx = active_child_idx ^ 1;
                        let not_ai = inactive_child_idx & 1;
                        let inactive_child = &mut lvl1[inactive_child_idx][i];
                        let correct_sum = *inactive_child ^ tree_grp.sums[not_ai][d][i];
                        *inactive_child =
                            correct_sum ^ my_sums[not_ai][i] ^ self.base_ots[(i + g, d)];
                    }
                }
            }
            let lvl = if out_fmt == OutFormat::Interleaved {
                get_level_output(&mut output, g, domain)
            } else {
                get_level(&mut tree, depth)
            };

            let d = depth - 1;
            for j in 0..PARALLEL_TREES {
                let active_child_idx = points[j + g];
                let inactive_child_idx = active_child_idx ^ 1;
                let not_ai = inactive_child_idx & 1;

                let mask_in = [
                    self.base_ots[(g + j, d)],
                    self.base_ots[(g + j, d)] ^ Block::ONES,
                ];
                let masks = FIXED_KEY_HASH.cr_hash_blocks(&mask_in);

                let ots: [Block; 2] =
                    array::from_fn(|i| tree_grp.last_ots[j][2 * not_ai + i] ^ masks[i]);

                let [inactive_child, active_child] =
                    get_inactive_active_child(j, lvl, inactive_child_idx, active_child_idx);

                // Fix the sums we computed previously to not include the
                // incorrect child values.
                let inactive_sum = my_sums[not_ai][j] ^ *inactive_child;
                let active_sum = my_sums[not_ai ^ 1][j] ^ *active_child;
                *inactive_child = ots[0] ^ inactive_sum;
                *active_child = ots[1] ^ active_sum;
            }
            if out_fmt != OutFormat::Interleaved {
                todo!()
            }
        }
        output
    }

    pub fn get_points(&self, out_fmt: OutFormat) -> Vec<usize> {
        match out_fmt {
            OutFormat::Interleaved => {
                let mut points = self.get_points(OutFormat::ByLeafIndex);
                let total_trees = points.len();
                for (i, point) in points.iter_mut().enumerate() {
                    *point = interleave_point(*point, i, total_trees, self.conf.domain(), out_fmt)
                }
                points
            }
            OutFormat::ByLeafIndex => self
                .base_choices
                .rows()
                .into_iter()
                .map(|choice_bits| get_active_path(choice_bits.iter().copied()))
                .collect(),
            _ => todo!()
        }
    }

    pub fn sample_choice_bits<R: RngCore + CryptoRng>(
        conf: PprfConfig,
        modulus: usize,
        out_fmt: OutFormat,
        rng: &mut R,
    ) -> Array2<u8> {
        let rows = conf.pnt_count().next_multiple_of(PARALLEL_TREES);
        let cols = conf.depth();
        let mut choices = Array2::zeros([rows, cols]);
        for (i, mut choice_row) in choices.rows_mut().into_iter().enumerate() {
            match out_fmt {
                OutFormat::ByLeafIndex => {
                    let mut idx;
                    loop {
                        choice_row
                            .iter_mut()
                            .for_each(|choice| *choice = rng.gen::<bool>() as u8);
                        idx = get_active_path(choice_row.iter().copied());
                        if idx < modulus {
                            break;
                        }
                    }
                }
                OutFormat::Interleaved => {
                    // make sure that atleast the first element of this tree
                    // is within the modulus.
                    let mut idx = interleave_point(0, i, conf.pnt_count, conf.domain, out_fmt);
                    assert!(idx < modulus, "Iteration {i}, failed: {idx} < {modulus}");
                    loop {
                        choice_row
                            .iter_mut()
                            .for_each(|choice| *choice = rng.gen::<bool>() as u8);
                        idx = get_active_path(choice_row.iter().copied());
                        idx = interleave_point(idx, i, conf.pnt_count, conf.domain, out_fmt);
                        if idx < modulus {
                            break;
                        }
                    }
                }
                _ => todo!()
            }
        }

        choices
    }
}

// Returns the i'th level of the current PARALLEL_TREES trees. The
// children of node j on level i are located at 2*j and
// 2*j+1  on level i+1.
fn get_level(tree: &mut [[Block; PARALLEL_TREES]], i: usize) -> &mut [[Block; PARALLEL_TREES]] {
    let size = 1 << i;
    let offset = size - 1;
    &mut tree[offset..offset + size]
}

// Return the i'th and (i+1)'th level
fn get_cons_levels(
    tree: &mut [[Block; PARALLEL_TREES]],
    i: usize,
) -> (
    &mut [[Block; PARALLEL_TREES]],
    &mut [[Block; PARALLEL_TREES]],
) {
    let size0 = 1 << i;
    let offset0 = size0 - 1;
    let tree = &mut tree[offset0..];
    let (level0, rest) = tree.split_at_mut(size0);
    let size1 = 1 << (i + 1);
    debug_assert_eq!(size0 + offset0, size1 - 1);
    let level1 = &mut rest[..size1];
    (level0, level1)
}

fn get_level_output(
    output: &mut Array2<Block>,
    tree_idx: usize,
    domain: usize,
) -> &mut [[Block; PARALLEL_TREES]] {
    // TODO not sure if can use Array2, since it is column major order
    let out = cast_slice_mut(output.as_slice_mut().unwrap());
    let forest = tree_idx / PARALLEL_TREES;
    assert_eq!(tree_idx % PARALLEL_TREES, 0);
    // let size = 1 << (conf.depth);
    let start = forest * domain;
    &mut out[start..start + domain]
}

fn get_active_path<I>(choice_bits: I) -> usize
where
    I: Iterator<Item = u8> + ExactSizeIterator,
{
    let len = choice_bits.len();
    choice_bits.enumerate().fold(0, |point, (i, cb)| {
        let shift = len - i - 1;
        point | ((1 ^ cb as usize) << shift)
    })
}

fn get_inactive_active_child(
    tree: usize,
    lvl: &mut [[Block; PARALLEL_TREES]],
    inactive_child_idx: usize,
    active_child_idx: usize,
) -> [&mut Block; 2] {
    let children = match active_child_idx.cmp(&inactive_child_idx) {
        Ordering::Less => {
            let (left, right) = lvl.split_at_mut(inactive_child_idx);
            [&mut right[0], &mut left[active_child_idx]]
        }
        Ordering::Greater => {
            let (left, right) = lvl.split_at_mut(active_child_idx);
            [&mut left[inactive_child_idx], &mut right[0]]
        }
        Ordering::Equal => {
            unreachable!("Impossible, active and inactive indices are always different")
        }
    };
    children.map(|arr| &mut arr[tree])
}

fn interleave_point(
    point: usize,
    tree_idx: usize,
    total_trees: usize,
    domain: usize,
    out_fmt: OutFormat,
) -> usize {
    match out_fmt {
        OutFormat::ByLeafIndex | OutFormat::ByTreeIndex => {
            panic!("interleave_point called on OutFormat::Plain")
        }
        // OutFormat::InterleavedTransposed => {
        //     let num_sets = total_trees / 8;

        //     let set_idx = tree_idx / 8;
        //     let sub_idx = tree_idx % 8;

        //     let section_idx = point / 16;
        //     let pos_idx = point % 16;

        //     let set_offset = set_idx * 128;
        //     let sub_offset = sub_idx + 8 * pos_idx;
        //     let sec_offset = section_idx * num_sets * 128;

        //     set_offset + sub_offset + sec_offset
        // }
        OutFormat::Interleaved => {
            if domain <= point {
                return usize::MAX;
            }
            let sub_tree = tree_idx % PARALLEL_TREES;
            let forest = tree_idx / PARALLEL_TREES;
            (forest * domain + point) * PARALLEL_TREES + sub_tree
        }
    }
}

// Create a pair of fixed key aes128 ciphers
fn create_fixed_aes() -> [Aes128; 2] {
    [
        Aes128::new(
            &91389970179024809574621370423327856399_u128
                .to_le_bytes()
                .into(),
        ),
        Aes128::new(
            &297966570818470707816499469807199042980_u128
                .to_le_bytes()
                .into(),
        ),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PprfConfig {
    pnt_count: usize,
    domain: usize,
    depth: usize,
}

impl PprfConfig {
    /// Create a PprfConfig
    ///
    /// # Panics
    /// If `pnt_count % `[`PARALLEL_TREES`]` != 0`
    pub fn new(domain: usize, pnt_count: usize) -> Self {
        // assert_eq!(
        //     0,
        //     pnt_count % PARALLEL_TREES,
        //     "pnt_count must be divisable by {PARALLEL_TREES}"
        // );
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

impl OutFormat {
    // returns (rows, cols)
    fn out_dims(&self, conf: &PprfConfig) -> (usize, usize) {
        match self {
            OutFormat::Interleaved => (conf.pnt_count * conf.domain, 1),
            OutFormat::ByLeafIndex | OutFormat::ByTreeIndex => todo!(),
        }
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

#[cfg(test)]
mod tests {
    use ndarray::Array2;
    use rand::{rngs::StdRng, CryptoRng, Rng, RngCore, SeedableRng};
    use seec_core::{utils::xor_inplace, Block};
    use seec_net::testing::local_conn;

    use crate::{OutFormat, PprfConfig, RegularPprfReceiver, RegularPprfSender, PARALLEL_TREES};

    pub fn fake_base<R: RngCore + CryptoRng>(
        conf: PprfConfig,
        modulus: usize,
        out_fmt: OutFormat,
        rng: &mut R,
    ) -> (Array2<[Block; 2]>, Array2<Block>, Array2<u8>) {
        let base_ot_count = conf.base_ot_count();
        let msg2: Vec<[Block; 2]> = (0..base_ot_count).map(|_| rng.gen()).collect();
        let choices = RegularPprfReceiver::sample_choice_bits(conf, modulus, out_fmt, rng);
        let msg = msg2
            .iter()
            .zip(choices.iter())
            .map(|(m, c)| m[*c as usize])
            .collect();

        let msg2 = Array2::from_shape_vec([conf.pnt_count(), conf.depth()], msg2).unwrap();
        let msg = Array2::from_shape_vec([conf.pnt_count(), conf.depth()], msg).unwrap();

        (msg2, msg, choices)
    }

    #[tokio::test]
    async fn test_pprf_interleaved() {
        let conf = PprfConfig::new(334, 5 * PARALLEL_TREES);
        let out_fmt = OutFormat::Interleaved;
        let mut rng = StdRng::seed_from_u64(42);

        let (c1, c2) = local_conn().await.unwrap();
        let (sender_base_ots, receiver_base_ots, base_choices) =
            fake_base(conf, conf.domain() * conf.pnt_count(), out_fmt, &mut rng);

        let sender = RegularPprfSender::new_with_conf(c1, conf, sender_base_ots);
        let receiver =
            RegularPprfReceiver::new_with_conf(c2, conf, receiver_base_ots, base_choices);
        let points = receiver.get_points(out_fmt);
        let seed = rng.gen();
        let (s_out, r_out) = tokio::join!(
            sender.expand(Block::ONES, seed, out_fmt),
            receiver.expand(out_fmt)
        );
        let out = s_out ^ r_out;
        for (i, blk) in out.iter().enumerate() {
            let f = points.contains(&i);
            let exp = if f { Block::ONES } else { Block::ZERO };
            assert_eq!(exp, *blk, "block {i} not as expected");
        }
    }
}
