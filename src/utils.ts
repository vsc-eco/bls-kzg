import * as Crypto from 'crypto'
import { bls12_381 as bls, } from '@noble/curves/bls12-381';
import * as galois from '@guildofweavers/galois'
import { ProjPointType } from '@noble/curves/abstract/weierstrass';


export type Fp2 = typeof bls.fields.Fp2
export type G1Point = ProjPointType<bigint>
export type G2Point = typeof bls.G2.ProjectivePoint.BASE


export function sha256(data) {
    // returns Buffer
    return Crypto.createHash('sha256').update(data).digest()
}

export const PRIME_MODULUS = bls.G1.CURVE.n
export const PRIME_FIELD = galois.createPrimeField(PRIME_MODULUS)


//Real world usage requires a multiparty trusted setup. 
export const trustedSetupKey = 'ebc388ab83362c66a69d80da50ed2f7e3e6a7be8c56722493cf17a4d0e6c774c'


//NOTE: g1Setup[0...n] and g2Setup[0...n] are paired.

export const generateG1Setup = (n: number): Array<G1Point> => {
    let out: G1Point[] = []
    const s = bls.G1.normPrivateKeyToScalar(sha256(`${trustedSetupKey}`));
    for(let x = 0; x < n; x++) { 
        const key = bls.G1.ProjectivePoint.fromPrivateKey(bls.fields.Fr.pow(s, BigInt(x)))
        out.push(key)
    }
    return out;
}

export const generateG2Setup = (n: number) => { 
    const s = bls.G2.normPrivateKeyToScalar(sha256(`${trustedSetupKey}`))
    const out: (ReturnType<typeof bls.G2.ProjectivePoint.fromPrivateKey>)[] = []
    for(let x = 0; x < n; x++) {
        const key = bls.G2.ProjectivePoint.fromPrivateKey(bls.fields.Fr.pow(s, BigInt(x)))
        out.push(key)
    }
    return out;
}
