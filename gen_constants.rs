// Temporary script to generate Poseidon2 round constants for width 8
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_field::PrimeField64;
use p3_poseidon2::Poseidon2;

fn main() {
    // Create Poseidon2 with deterministic seed (same as config.rs)
    let perm = Poseidon2Goldilocks::<8>::new_from_rng_128(&mut DeterministicRng(42));
    
    // Test permutation on a known input
    let mut state = [Goldilocks::ZERO; 8];
    state[0] = Goldilocks::from_u64(1);
    state[1] = Goldilocks::from_u64(2);
    
    // Clone to get the output
    let mut output = state.clone();
    use p3_symmetric::Permutation;
    perm.permute_mut(&mut output);
    
    println!("Input:  {:?}", state.iter().map(|x| x.as_canonical_u64()).collect::<Vec<_>>());
    println!("Output: {:?}", output.iter().map(|x| x.as_canonical_u64()).collect::<Vec<_>>());
    
    // Print round constants
    // We need to access the internal state of Poseidon2...
    // Actually, let's just verify the hash works and use the same Poseidon2 in both trace gen and AIR
}

struct DeterministicRng(u64);
impl rand::RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            let val = self.next_u64();
            let remaining = dest.len() - i;
            let to_copy = remaining.min(8);
            dest[i..i + to_copy].copy_from_slice(&val.to_le_bytes()[..to_copy]);
            i += to_copy;
        }
    }
}
impl rand::CryptoRng for DeterministicRng {}
