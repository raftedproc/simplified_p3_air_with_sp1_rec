# RandomX program execution implementation in Plonky3

This repo implements a RandomX program execution and prover using the Plonky3 framework to generate/check execution of RandomX algo.

This version uses Gnark to wrap STARK into Groth16, so to run this version one needs Go compiler available.

To setup Groth16 keys and circuit first run 
```
SP1_DEV=1 RUST_BACKTRACE=full RUST_LOG=info RUSTFLAGS='-C target-cpu=native' cargo run --release -- -p 1 -r 1
```

Then you have to move produced Groth16 circuit-related info
```
cp -rp ~/.sp1/circuits/dev/* ~/.sp1/circuits/groth16/v3.0.0/
```

And finally run the program
```
FRI_QUERIES=1 RUST_BACKTRACE=full RUST_LOG=info RUSTFLAGS='-C target-cpu=native' cargo run --release -- -p 1 -r 1
```