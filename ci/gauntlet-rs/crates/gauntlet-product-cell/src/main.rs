use gauntlet_product_cell::{run_actor, run_exec_gate, CellError};

fn run() -> Result<(), CellError> {
    let mut args = std::env::args_os().skip(1);
    let action = args.next();
    if action.as_deref() == Some(std::ffi::OsStr::new("actor")) {
        if args.next().is_some() {
            return Err(CellError("actor accepts no arguments"));
        }
        return run_actor();
    }
    if action.as_deref() != Some(std::ffi::OsStr::new("exec-gate")) {
        return Err(CellError(
            "usage: gauntlet-product-cell actor | exec-gate ABSOLUTE_PRODUCT_PROGRAM [ARGUMENTS]",
        ));
    }
    let argv = args
        .map(|arg| {
            arg.into_string()
                .map_err(|_| CellError("product argv must be UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    match run_exec_gate(&argv) {
        Ok(never) => match never {},
        Err(error) => Err(error),
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(126);
    }
}
