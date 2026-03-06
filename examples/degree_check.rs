use davinci_stark::air::{BallotAir, PV_COUNT, TRACE_HEIGHT};
use davinci_stark::columns::TRACE_WIDTH;
use p3_goldilocks::Goldilocks;
use p3_field::extension::BinomialExtensionField;
use p3_miden_prover::{get_symbolic_constraints, AirWithBoundaryConstraints};
use p3_miden_prover::StarkGenericConfig;
use davinci_stark::config::{SyncBallotConfig, make_config};
use core::marker::PhantomData;
use p3_util::log2_strict_usize;

type Challenge = BinomialExtensionField<Goldilocks, 2>;

fn main() {
    let air = BallotAir::new();
    let config = make_config();
    
    // Same wrapping as the prover does
    let wrapped = AirWithBoundaryConstraints::<SyncBallotConfig, BallotAir> {
        inner: &air,
        phantom: PhantomData,
    };
    
    let constraints = get_symbolic_constraints::<Goldilocks, Challenge, _>(&wrapped, 0, PV_COUNT, 0, 0);
    let max_degree = constraints.iter().map(|c| c.degree_multiple()).max().unwrap_or(0);
    println!("With AirWithBoundaryConstraints wrapper:");
    println!("Number of constraints: {}", constraints.len());
    println!("Max constraint degree_multiple: {}", max_degree);
    
    let log_quotient = p3_util::log2_ceil_usize((max_degree.max(2)) - 1);
    println!("log_num_quotient_chunks = {}", log_quotient);
    
    let log_degree = log2_strict_usize(TRACE_HEIGHT);
    let is_zk = config.is_zk();
    let log_ext_degree = log_degree + is_zk;
    
    println!("log_degree = {}, is_zk = {}, log_ext_degree = {}", log_degree, is_zk, log_ext_degree);
    
    let log_blowup = 5;
    let lde_height = TRACE_HEIGHT * (1 << log_blowup);
    let quotient_domain_size = 1 << (log_ext_degree + log_quotient);
    
    println!("LDE height = {}", lde_height);
    println!("Quotient domain size = {}", quotient_domain_size);
    println!("Assertion: {} >= {} = {}", lde_height, quotient_domain_size, lde_height >= quotient_domain_size);
}
