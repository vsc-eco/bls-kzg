# KZG Commitments Over BLS12-381

Proof of concept KZG commitments using BLS12-381 curves using [noble-curves](https://github.com/paulmillr/noble-curves) and [galois](https://github.com/GuildOfWeavers/galois)

This library is based off [libkzg](https://github.com/weijiekoh/libkzg) by [weijiekoh](https://github.com/weijiekoh). 
We specifically used BLS12-381 instead of bn254 due to security issues and integration with the rest of the VSC tech stack. To learn more about what we are building please go to [our website](https://vsc.eco)

TBD

# Implementation notes

- The trusted setup used within this library is hardcoded and cannot securly generate proofs. A proper trusted setup much be used.
- Both single and multi proofs use G2 point as the proof.
- Pure Javascript with no bindings

# Tests
```
PASS  src/__tests__/kzg.test.ts (18.857 s)
  kzg/apk proofs on bls12-381
    commit, prove, and verify the polynomial 
      √ compute coefficientes (small) (4 ms)
      √ compute coefficientes (large) (2 ms)
      √ generate a KZG commitment (93 ms)
      √ generate a KZG proof (57 ms)
      √ verify a KZG proof (151 ms)
      √ generate and verify a multi KZG proof (332 ms)
```

# License

MIT
