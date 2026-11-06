//! Explicit one-use feature audit. This does not install a production worker.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = (|| -> Result<serde_json::Value, String> {
        let path = std::path::Path::new(args.get(1).ok_or("private feature journal required")?);
        let journal = gauntlet_host_state::FeatureIntentJournal::open(path)?;
        match args.first().map(String::as_str) {
            Some("record") if args.len()==4=>{
                let pins=gauntlet_host_state::read_feature_run_pins(std::path::Path::new(&args[2]))?;
                let operations=gauntlet_host_state::public_vm_operations(Some(&args[3])).map_err(|e|e.to_string())?;
                let intent=journal.record(pins,&operations)?;
                Ok(serde_json::json!({"intent_sha256":intent.digest()?,"intent":serde_json::from_slice::<serde_json::Value>(&intent.bytes()?).map_err(|e|e.to_string())?}))
            },
            Some("run") if args.len()==4=>{
                let intent=journal.read(&args[2])?;
                if intent.digest()?!=args[3] {return Err("outside feature intent digest differs".into());}
                journal.execute_once(&intent)
            },
            Some("read") if args.len()==4=>{
                let intent=journal.read(&args[2])?;
                if intent.digest()?!=args[3] {return Err("outside feature intent digest differs".into());}
                journal.read_retained(&intent)
            },
            Some("repair") if args.len()==5=>{
                let intent=journal.read(&args[2])?;
                if intent.digest()?!=args[3] {return Err("outside feature intent digest differs".into());}
                journal.repair(&intent,&args[4])
            },
            _=>Err("usage: gauntlet-host-feature-audit record PRIVATE_JOURNAL PRIVATE_PINS VM | run|read PRIVATE_JOURNAL AUDIT_ID INTENT_SHA256 | repair PRIVATE_JOURNAL AUDIT_ID INTENT_SHA256 REPAIR_BINARY_SHA256".into()),
        }
    })();
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("feature audit unavailable: {error}");
            std::process::exit(2);
        }
    }
}
