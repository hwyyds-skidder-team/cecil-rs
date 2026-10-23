//! Line-oriented differential reader probe; input paths arrive on stdin.
use std::io::{self, BufRead};

fn main() {
    for path in io::stdin().lock().lines() {
        let path = path.expect("stdin");
        let result = std::panic::catch_unwind(|| {
            let bytes = std::fs::read(&path)?;
            let asm = cecil::AssemblyDefinition::read(&bytes)?;
            for (id, _) in asm.main.iter_types() {
                std::hint::black_box(asm.main.type_full_name(id));
            }
            Ok::<_, cecil_core::Error>(asm.main.methods.len())
        });
        match result {
            Ok(Ok(methods)) => println!("ok\t{methods}"),
            Ok(Err(error)) => {
                println!("error\t{}", error.to_string().replace(['\r', '\n', '\t'], " "))
            }
            Err(_) => println!("panic"),
        }
    }
}
