use davinci_stark::columns::TRACE_WIDTH;

#[test]
fn trace_width_stays_below_browser_budget() {
    assert!(
        TRACE_WIDTH <= 520,
        "TRACE_WIDTH={} is too wide for the browser budget",
        TRACE_WIDTH
    );
}
