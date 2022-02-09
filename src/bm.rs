//! This file implements the Berlekamp-Massey algorithm
//! see <http://crypto.stanford.edu/~mironov/cs359/massey.pdf>

use crate::gf::{gf_frac, gf_mul, Gf};
use crate::params::SYS_T;

pub fn min(a: usize, b: usize) -> usize {
    let c = (a < b) as isize;
    let d = c << (isize::BITS - 1);
    let e = (d >> (isize::BITS - 1)) as usize;
    (a & e) | (b & !e)
}

/// The Berlekamp-Massey algorithm.
/// Uses `s` as input (sequence of field elements)
/// and `out` as output (minimal polynomial of `s`)
pub fn bm(out: &mut [Gf; SYS_T + 1], s: &mut [Gf; 2 * SYS_T]) {
    let mut l: u16 = 0;
    let mut mle: u16;
    let mut mne: u16;

    let mut t = [0u16; SYS_T + 1];
    let mut c = [0u16; SYS_T + 1];
    let mut b = [0u16; SYS_T + 1];

    let mut base: Gf = 1;

    b[1] = 1;
    c[0] = 1;

    for n in 0..(2 * SYS_T) {
        let mut d: Gf = 0;
        for i in 0..=min(n, SYS_T) {
            d ^= gf_mul(c[i], s[n - i]);
        }
        mne = d;
        mne = mne.wrapping_sub(1);
        mne >>= 15;
        mne = mne.wrapping_sub(1);

        mle = n as u16;
        mle = mle.wrapping_sub(2 * l);
        mle >>= 15;
        mle = mle.wrapping_sub(1);
        mle &= mne;

        for i in 0..=SYS_T {
            t[i] = c[i];
        }

        let f: Gf = gf_frac(base, d);

        for i in 0..=SYS_T {
            c[i] ^= gf_mul(f, b[i]) & mne;
        }

        l = (l & !mle) | ((n as u16 + 1 - l) & mle);

        for i in 0..=SYS_T {
            b[i] = (b[i] & !mle) | (t[i] & mle);
        }

        base = (base & !mle) | (d & mle);

        for i in (1..=SYS_T).rev() {
            b[i] = b[i - 1];
        }

        b[0] = 0;
    }

    for i in 0..=SYS_T {
        out[i] = c[SYS_T - i];
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "mceliece8192128f", test))]
    use super::*;

    #[cfg(all(feature = "mceliece8192128f", test))]
    fn test_simple_bm() {
        assert_eq!(SYS_T + 1, 129);

        let compare_array: [u16; 129] = [
            7438, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794, 2310, 1794, 5390, 1794,
            2310, 1794, 7432, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794, 2310, 1794,
            5390, 1794, 2310, 1794, 7433, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794,
            2310, 1794, 5390, 1794, 2310, 1794, 7432, 1794, 2310, 1794, 5390, 1794, 2310, 1794,
            3333, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 7435, 1794, 2310, 1794, 5390, 1794,
            2310, 1794, 3333, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 7432, 1794, 2310, 1794,
            5390, 1794, 2310, 1794, 3333, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 7433, 1794,
            2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794, 2310, 1794, 5390, 1794, 2310, 1794,
            7432, 1794, 2310, 1794, 5390, 1794, 2310, 1794, 3333, 1794, 2310, 1794, 5390, 1794,
            2310, 1794, 1,
        ];

        let mut locator = [0u16; SYS_T + 1];
        let mut s = [0u16; SYS_T * 2];

        for i in 0..s.len() {
            s[i] = i as u16;
        }

        bm(&mut locator, &mut s);

        assert_eq!(locator, compare_array);
    }

    #[cfg(all(feature = "mceliece8192128f", test))]
    fn test_first_round_bm() {
        let compare_array: [u16; SYS_T + 1] = [
            250, 2904, 5820, 5817, 2913, 1022, 2568, 7340, 3511, 2713, 85, 4952, 1828, 2015, 7604,
            2984, 1239, 2877, 7428, 4869, 2483, 6063, 8176, 3705, 424, 8039, 4633, 5599, 7821, 135,
            1415, 1301, 6104, 5314, 5565, 3786, 7390, 757, 2606, 1932, 17, 7336, 4531, 3302, 5470,
            567, 7032, 8130, 1393, 890, 6316, 7419, 2006, 5838, 1596, 5978, 6030, 2636, 4627, 3638,
            1462, 5083, 2545, 3881, 1928, 5507, 7463, 6335, 316, 414, 6699, 1307, 3034, 1963, 7714,
            3578, 7365, 6709, 4344, 5522, 1090, 2853, 4218, 781, 7971, 5690, 2696, 7453, 1203,
            1643, 1780, 6298, 3736, 1049, 5825, 5595, 7498, 6024, 1202, 1389, 1897, 5504, 5230,
            210, 2277, 4325, 6846, 2774, 3679, 3117, 3196, 5600, 514, 7370, 500, 3992, 5096, 5351,
            468, 3717, 7980, 3451, 3225, 2781, 5999, 7016, 2945, 5882, 1,
        ];

        let mut s_input: [u16; SYS_T * 2] = [
            880, 3960, 5628, 6227, 8148, 197, 7918, 2029, 5149, 7056, 8108, 6492, 1462, 5537, 3344,
            4900, 2123, 358, 4972, 5577, 4403, 6221, 7305, 3919, 1558, 2336, 1214, 1927, 7060,
            3745, 2771, 6670, 3751, 7370, 1066, 7084, 7449, 5111, 151, 6434, 3333, 8065, 1777,
            6515, 5200, 863, 3672, 5226, 6922, 5672, 6099, 4435, 5755, 2979, 1020, 6852, 4638,
            3025, 2847, 6935, 913, 350, 5446, 4889, 4582, 6441, 491, 7707, 5416, 1458, 2822, 7940,
            6629, 3575, 4596, 2605, 7892, 44, 2732, 5205, 3684, 4369, 5912, 4847, 5410, 6654, 6374,
            7382, 2239, 6320, 6693, 4911, 2529, 2645, 2943, 8154, 4484, 3178, 3240, 8168, 2289,
            7225, 7020, 6572, 6116, 6189, 1483, 608, 7097, 2147, 1897, 3630, 489, 782, 3211, 3285,
            5869, 6191, 1870, 4220, 52, 7258, 6395, 6340, 454, 2376, 6624, 5695, 1466, 1073, 3801,
            4877, 3545, 1650, 1266, 2535, 8170, 1212, 2338, 1343, 5208, 1920, 439, 245, 1960, 999,
            5874, 6650, 2865, 4748, 1198, 4026, 2082, 6153, 1791, 2808, 7483, 3037, 3226, 7678,
            354, 6797, 2828, 5052, 3729, 2449, 6036, 4766, 3447, 7651, 7571, 976, 7953, 1754, 5663,
            8100, 4419, 142, 4079, 7622, 1683, 1919, 3171, 7323, 3485, 6564, 811, 6210, 3812, 6148,
            1260, 6897, 3464, 1556, 6030, 304, 5971, 561, 4260, 329, 5878, 2601, 3253, 5308, 4361,
            7378, 3069, 2078, 3098, 7988, 3483, 4221, 7453, 4336, 3939, 3961, 1745, 4394, 4203,
            4145, 2386, 6205, 381, 3261, 1285, 2010, 988, 4296, 5378, 1641, 6729, 8000, 607, 4548,
            6065, 495, 5566, 2803, 1550, 6131, 3964, 6534, 7694, 4434, 8105, 829, 1316, 3689, 814,
            5640, 3069, 1448, 7585, 3008, 6036, 2505,
        ];

        let mut locator = [0u16; SYS_T + 1];
        bm(&mut locator, &mut s_input);

        assert_eq!(locator, compare_array);
    }
}
