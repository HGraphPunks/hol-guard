use std::path::Path;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let result = if args.len() == 3 {
        gauntlet_cell_rootfs::construct_from_file(Path::new(&args[1]), &args[2])
    } else {
        Err("usage: gauntlet-cell-rootfs EXACT_ROOT_DECLARATION OUTSIDE_SHA256".into())
    };
    if let Err(error) = result {
        eprintln!("gauntlet-cell-rootfs: {error}");
        std::process::exit(2);
    }
}
