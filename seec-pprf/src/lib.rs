//! # Distributed Puncturable Pseudorandom Function (PPRF) Implementation
use std::{array, cmp::Ordering, mem};

use aes::{
    cipher::{BlockCipherEncrypt, KeyInit},
    Aes128,
};
use bytemuck::{cast_slice, cast_slice_mut};
use futures::{SinkExt, StreamExt};
use ndarray::Array2;
use rand::{distributions::Uniform, prelude::Distribution, CryptoRng, Rng, RngCore, SeedableRng};
use seec_core::{
    aes_hash::FIXED_KEY_HASH, aes_rng::AesRng, alloc::allocate_zeroed_vec, buf::Buf,
    tokio_rayon::spawn_compute, utils::{log2_ceil, xor_inplace}, Block, AES_PAR_BLOCKS,
};
use seec_net::Connection;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::unbounded_channel;

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
    last_ots: Vec<[Block; 4]>,
}

impl RegularPprfSender {
    pub fn new_with_conf(conn: Connection, conf: PprfConfig, base_ots: Vec<[Block; 2]>) -> Self {
        assert_eq!(conf.base_ot_count(), base_ots.len());
        let base_ots = Array2::from_shape_vec([conf.pnt_count(), conf.depth()], base_ots)
            .expect("base_ots.len() is checked before");
        Self {
            conn,
            conf,
            base_ots,
        }
    }

    pub async fn expand(
        mut self,
        value: Block,
        seed: Block,
        out_fmt: OutFormat,
        out: &mut impl Buf<Block>,
    ) {
        assert_eq!(self.conf.size(), out.len());
        let mut output = mem::take(out);
        let (mut tx, _) = self.conn.stream().await.unwrap();
        let (send, mut recv) = unbounded_channel();
        let jh = spawn_compute(move || {
            let aes = create_fixed_aes();
            let depth = self.conf.depth();
            let pnt_count = self.conf.pnt_count();
            let domain = self.conf.domain();

            let mut rng = AesRng::from_seed(seed);
            let dd = match out_fmt {
                OutFormat::Interleaved => depth,
                _ => depth + 1,
            };

            let mut tree: Vec<[Block; PARALLEL_TREES]> =
                allocate_zeroed_vec(2_usize.pow(dd as u32));

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
                        for (aes, sums) in aes.iter().zip(&mut tree_grp.sums) {
                            let child = &mut lvl1[child_idx];
                            let sum = &mut sums[d];
                            aes.encrypt_blocks_b2b(cast_slice(parent), cast_slice_mut(child))
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
                            *sum ^= self.base_ots[(g + j, depth - 1 - d)][idx ^ 1];
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
                        self.base_ots[(g + j, 0)][1],
                        self.base_ots[(g + j, 0)][1] ^ Block::ONES,
                        self.base_ots[(g + j, 0)][0],
                        self.base_ots[(g + j, 0)][0] ^ Block::ONES,
                    ];
                    let masks = FIXED_KEY_HASH.cr_hash_blocks(&mask_in);
                    xor_inplace(&mut tree_grp.last_ots[j], &masks);
                }
                tree_grp.sums[0].truncate(depth - 1);
                tree_grp.sums[1].truncate(depth - 1);

                send.send(tree_grp).unwrap();
                if out_fmt != OutFormat::Interleaved {
                    let last_lvl = get_level(&mut tree, depth);
                    copy_out(last_lvl, &mut output, g, out_fmt, self.conf);
                }
            }
            output
        });

        while let Some(tree_group) = recv.recv().await {
            tx.send(tree_group).await.unwrap();
        }

        *out = jh.await;
    }
}

impl RegularPprfReceiver {
    pub fn new_with_conf(
        conn: Connection,
        conf: PprfConfig,
        base_ots: Vec<Block>,
        base_choices: Vec<u8>,
    ) -> Self {
        assert_eq!(conf.base_ot_count(), base_ots.len());
        assert_eq!(conf.base_ot_count(), base_choices.len());
        let base_ots = Array2::from_shape_vec([conf.pnt_count(), conf.depth()], base_ots)
            .expect("base_ots.len() is checked before");
        let base_choices = Array2::from_shape_vec([conf.pnt_count(), conf.depth()], base_choices)
            .expect("base_ots.len() is checked before");
        Self {
            conn,
            conf,
            base_ots,
            base_choices,
        }
    }

    pub async fn expand(mut self, out_fmt: OutFormat, out: &mut impl Buf<Block>) {
        assert_eq!(self.conf.size(), out.len());
        let mut output = mem::take(out);
        let (_, mut rx) = self.conn.stream().await.unwrap();
        let (send, recv) = std::sync::mpsc::channel();
        let jh = spawn_compute(move || {
            let aes = create_fixed_aes();
            let points = self.get_points(OutFormat::ByLeafIndex);
            let depth = self.conf.depth();
            let pnt_count = self.conf.pnt_count();
            let domain = self.conf.domain();
            let dd = match out_fmt {
                OutFormat::Interleaved => depth,
                _ => depth + 1,
            };
            let mut tree: Vec<[Block; PARALLEL_TREES]> =
                allocate_zeroed_vec(2_usize.pow(dd as u32));

            for g in (0..pnt_count).step_by(PARALLEL_TREES) {
                let tree_grp: TreeGrp = recv.recv().unwrap();
                assert_eq!(g, tree_grp.g);

                if depth > 1 {
                    let lvl1 = get_level(&mut tree, 1);
                    for i in 0..PARALLEL_TREES {
                        let active = self.base_choices[(i + g, depth - 1)] as usize;
                        lvl1[active ^ 1][i] =
                            self.base_ots[(i + g, depth - 1)] ^ tree_grp.sums[active ^ 1][0][i];
                        lvl1[active][i] = Block::ZERO;
                    }
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
                        for (aes, sum) in aes.iter().zip(&mut my_sums) {
                            let child = &mut lvl1[child_idx];
                            aes.encrypt_blocks_b2b(cast_slice(parent), cast_slice_mut(child))
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
                            *inactive_child = correct_sum
                                ^ my_sums[not_ai][i]
                                ^ self.base_ots[(i + g, depth - 1 - d)];
                        }
                    }
                }
                let lvl = if out_fmt == OutFormat::Interleaved {
                    get_level_output(&mut output, g, domain)
                } else {
                    get_level(&mut tree, depth)
                };

                for j in 0..PARALLEL_TREES {
                    let active_child_idx = points[j + g];
                    let inactive_child_idx = active_child_idx ^ 1;
                    let not_ai = inactive_child_idx & 1;

                    let mask_in = [
                        self.base_ots[(g + j, 0)],
                        self.base_ots[(g + j, 0)] ^ Block::ONES,
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
                    let last_lvl = get_level(&mut tree, depth);
                    copy_out(last_lvl, &mut output, g, out_fmt, self.conf);
                }
            }
            output
        });

        while let Some(tree_grp) = rx.next().await {
            let tree_grp = tree_grp.unwrap();
            send.send(tree_grp).unwrap();
        }

        *out = jh.await;
    }

    pub fn get_points(&self, out_fmt: OutFormat) -> Vec<usize> {
        match out_fmt {
            OutFormat::Interleaved => {
                let mut points = self.get_points(OutFormat::ByLeafIndex);
                for (i, point) in points.iter_mut().enumerate() {
                    *point = interleave_point(*point, i, self.conf.domain())
                }
                points
            }
            OutFormat::ByLeafIndex => self
                .base_choices
                .rows()
                .into_iter()
                .map(|choice_bits| {
                    debug_assert_eq!(self.conf.depth(), choice_bits.len());
                    let point = get_active_path(choice_bits.iter().copied());
                    debug_assert!(point < self.conf.domain());
                    point
                })
                .collect(),
            _ => todo!(),
        }
    }

    pub fn sample_choice_bits<R: RngCore + CryptoRng>(conf: PprfConfig, rng: &mut R) -> Vec<u8> {
        let mut choices = vec![0_u8; conf.pnt_count() * conf.depth()];
        let dist = Uniform::new(0, conf.domain());
        for choice in choices.chunks_exact_mut(conf.depth()) {
            let mut idx = dist.sample(rng);
            for choice_bit in choice {
                *choice_bit = (idx & 1) as u8;
                idx >>= 1;
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
    output: &mut [Block],
    tree_idx: usize,
    domain: usize,
) -> &mut [[Block; PARALLEL_TREES]] {
    let out = cast_slice_mut(output);
    let forest = tree_idx / PARALLEL_TREES;
    debug_assert_eq!(tree_idx % PARALLEL_TREES, 0);
    let start = forest * domain;
    &mut out[start..start + domain]
}

fn get_active_path<I>(choice_bits: I) -> usize
where
    I: Iterator<Item = u8> + ExactSizeIterator,
{
    choice_bits
        .enumerate()
        .fold(0, |point, (i, cb)| point | ((cb as usize) << i))
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

fn interleave_point(point: usize, tree_idx: usize, domain: usize) -> usize {
    let sub_tree = tree_idx % PARALLEL_TREES;
    let forest = tree_idx / PARALLEL_TREES;
    (forest * domain + point) * PARALLEL_TREES + sub_tree
}

fn copy_out(
    last_lvl: &[[Block; 9]],
    output: &mut [Block],
    tree_idx: usize,
    out_fmt: OutFormat,
    conf: PprfConfig,
) {
    let total_trees = conf.pnt_count();
    let curr_size = PARALLEL_TREES.min(total_trees - tree_idx);
    let last_lvl: &[Block] = cast_slice(last_lvl);
    // assert_eq!(conf.domain(), last_lvl.len() / PARALLEL_TREES);
    let domain = conf.domain();
    match out_fmt {
        OutFormat::ByLeafIndex => {
            for leaf_idx in 0..domain {
                let o_idx = total_trees * leaf_idx + tree_idx;
                let i_idx = leaf_idx * PARALLEL_TREES;
                // todo copy from slice
                output[o_idx..curr_size + o_idx]
                    .copy_from_slice(&last_lvl[i_idx..curr_size + i_idx]);
            }
        }
        OutFormat::ByTreeIndex => todo!(),
        OutFormat::Interleaved => panic!("Do not copy_out for OutFormat::Interleaved"),
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
    /// - if `domain < 2`
    /// - if `domain % 2 != 0`
    /// - if `pnt_count % `[`PARALLEL_TREES`]` != 0`
    pub fn new(domain: usize, pnt_count: usize) -> Self {
        assert!(domain >= 2, "domain must be at least 2");
        assert_eq!(0, domain % 2, "domain must be even");
        assert_eq!(
            0,
            pnt_count % PARALLEL_TREES,
            "pnt_count must be divisable by {PARALLEL_TREES}"
        );
        let depth = log2_ceil(domain);
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

    pub fn size(&self) -> usize {
        self.domain() * self.pnt_count()
    }
}

/// Intended for testing. Generated suitable OTs and choice bits for a pprf
/// evaluation.
pub fn fake_base<R: RngCore + CryptoRng>(
    conf: PprfConfig,
    rng: &mut R,
) -> (Vec<[Block; 2]>, Vec<Block>, Vec<u8>) {
    let base_ot_count = conf.base_ot_count();
    let msg2: Vec<[Block; 2]> = (0..base_ot_count).map(|_| rng.gen()).collect();
    let choices = RegularPprfReceiver::sample_choice_bits(conf, rng);
    let msg = msg2
        .iter()
        .zip(choices.iter())
        .map(|(m, c)| m[*c as usize])
        .collect();
    (msg2, msg, choices)
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use seec_core::{alloc::HugePageMemory, buf::Buf, utils::xor_inplace, Block};
    use seec_net::testing::local_conn;

    use crate::{
        fake_base, OutFormat, PprfConfig, RegularPprfReceiver, RegularPprfSender, PARALLEL_TREES,
    };

    #[tokio::test]
    async fn test_pprf_by_leaf() {
        let conf = PprfConfig::new(334, 5 * PARALLEL_TREES);
        let out_fmt = OutFormat::ByLeafIndex;
        let mut rng = StdRng::seed_from_u64(42);

        let (c1, c2) = local_conn().await.unwrap();
        let (sender_base_ots, receiver_base_ots, base_choices) = fake_base(conf, &mut rng);

        let sender = RegularPprfSender::new_with_conf(c1, conf, sender_base_ots);
        let receiver =
            RegularPprfReceiver::new_with_conf(c2, conf, receiver_base_ots, base_choices);
        let points = receiver.get_points(out_fmt);
        eprintln!("{points:?}");
        let mut s_out = HugePageMemory::zeroed(conf.size());
        let mut r_out = HugePageMemory::zeroed(conf.size());
        let seed = rng.gen();
        tokio::join!(
            sender.expand(Block::ONES, seed, out_fmt, &mut s_out),
            receiver.expand(out_fmt, &mut r_out)
        );

        xor_inplace(&mut s_out, &r_out);

        for j in 0..points.len() {
            for i in 0..conf.domain() {
                let idx = i * points.len() + j;

                let exp = if points[j] == i {
                    Block::ONES
                } else {
                    Block::ZERO
                };
                assert_eq!(exp, s_out[idx]);
            }
        }
    }

    #[tokio::test]
    async fn test_pprf_interleaved_simple() {
        // Reduce size to minimum to debug
        let conf = PprfConfig::new(2, PARALLEL_TREES);
        let out_fmt = OutFormat::Interleaved;
        let mut rng = StdRng::seed_from_u64(42);

        let (c1, c2) = local_conn().await.unwrap();
        let (sender_base_ots, receiver_base_ots, base_choices) = fake_base(conf, &mut rng);

        // Print the base OTs to see correlation
        // println!("Sender base OTs: {:?}", sender_base_ots);
        // println!("Receiver base OTs: {:?}", receiver_base_ots);
        println!("Base choices: {:?}", base_choices);

        let sender = RegularPprfSender::new_with_conf(c1, conf, sender_base_ots);
        let receiver =
            RegularPprfReceiver::new_with_conf(c2, conf, receiver_base_ots, base_choices);
        let points = receiver.get_points(out_fmt);
        println!("Points: {:?}", points);
        let mut s_out = Vec::zeroed(conf.size());
        let mut r_out = Vec::zeroed(conf.size());
        let seed = rng.gen();
        tokio::join!(
            sender.expand(Block::ONES, seed, out_fmt, &mut s_out),
            receiver.expand(out_fmt, &mut r_out)
        );

        xor_inplace(&mut s_out, &r_out);
        println!("XORed output: {:?}", s_out);
        for (i, blk) in s_out.iter().enumerate() {
            let f = points.contains(&i);
            let exp = if f { Block::ONES } else { Block::ZERO };
            assert_eq!(exp, *blk, "block {i} not as expected");
        }
    }

    #[tokio::test]
    async fn test_pprf_interleaved() {
        let conf = PprfConfig::new(334, 5 * PARALLEL_TREES);
        let out_fmt = OutFormat::Interleaved;
        let mut rng = StdRng::seed_from_u64(42);

        let (c1, c2) = local_conn().await.unwrap();
        let (sender_base_ots, receiver_base_ots, base_choices) = fake_base(conf, &mut rng);

        let sender = RegularPprfSender::new_with_conf(c1, conf, sender_base_ots);
        let receiver =
            RegularPprfReceiver::new_with_conf(c2, conf, receiver_base_ots, base_choices);
        let points = receiver.get_points(out_fmt);
        let mut s_out = HugePageMemory::zeroed(conf.size());
        let mut r_out = HugePageMemory::zeroed(conf.size());
        let seed = rng.gen();
        tokio::join!(
            sender.expand(Block::ONES, seed, out_fmt, &mut s_out),
            receiver.expand(out_fmt, &mut r_out)
        );

        xor_inplace(&mut s_out, &r_out);
        for (i, blk) in s_out.iter().enumerate() {
            let f = points.contains(&i);
            let exp = if f { Block::ONES } else { Block::ZERO };
            assert_eq!(exp, *blk, "block {i} not as expected");
        }
    }
}
