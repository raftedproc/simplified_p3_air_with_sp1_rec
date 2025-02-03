# RandomX hash generation execution proved with SP1/Plonky3

Rudimentary RandomX program execution proving implementation using SP1 and Plonky3 frameworks. 
In a nutshell produces execution STARK proof with P3 and then uses recursive engine of SP1 to wrap the prove into Groth16 STARK.

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