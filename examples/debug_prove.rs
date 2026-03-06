use davinci_stark::air::{BallotAir, PV_COUNT};
use davinci_stark::columns::TRACE_WIDTH;
use davinci_stark::config::make_config;
use p3_goldilocks::Goldilocks;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_miden_prover::prove;

fn main() {
    let config = make_config();
    let air = BallotAir::new();
    
    // Create a minimal trace: all zeros, 1024 rows
    let height = 1024;
    let width = TRACE_WIDTH;
    let trace_data = vec![Goldilocks::ZERO; height * width];
    let trace = RowMajorMatrix::new(trace_data, width);
    let pv = vec![Goldilocks::ZERO; PV_COUNT];
    
    println!("Trace: {} x {}", height, width);
    println!("Attempting prove...");
    let _proof = prove(&config, &air, &trace, &pv);
    println!("Proof succeeded!");
}
