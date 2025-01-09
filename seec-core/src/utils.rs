pub fn xor_inplace(a: &mut [u8], b: &[u8]) {
    a.iter_mut().zip(b).for_each(|(a, b)| {
        *a ^= b;
    });
}
