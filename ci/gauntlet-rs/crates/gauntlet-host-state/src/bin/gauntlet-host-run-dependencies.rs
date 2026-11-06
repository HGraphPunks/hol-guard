use gauntlet_host_state::{
    public_vm_operations, read_dependency_run_pins, DependencyIntentJournal,
};
use std::path::Path;
fn run() -> Result<serde_json::Value, String> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 3 && !(args.len() == 5 && args[3] == "--vm") {
        return Err("usage: gauntlet-host-run-dependencies PRIVATE_INTENT_DIR PRIVATE_RUN_PINS_JSON [--vm VM_NAME]".into());
    }
    let pins = read_dependency_run_pins(Path::new(&args[2]))?;
    let operations =
        public_vm_operations(args.get(4).map(String::as_str)).map_err(|e| e.to_string())?;
    let journal = DependencyIntentJournal::open(Path::new(&args[1]))?;
    let intent = journal.record(pins, &operations)?;
    journal.execute_once(&intent)
}
fn main() {
    match run() {
        Ok(v) => println!("{v}"),
        Err(e) => {
            eprintln!("dependency preparation unavailable: {e}");
            std::process::exit(2);
        }
    }
}
