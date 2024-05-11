import * as assert from 'assert'
import * as galois from '@guildofweavers/galois'
import { bls12_381 as bls, } from '@noble/curves/bls12-381';

import {G1Point, G2Point, PRIME_MODULUS, generateG1Setup, generateG2Setup, sha256} from './utils'
import { genInterpolatingPoly, genZeroPoly } from './poly';
import { Hex } from '@noble/curves/abstract/utils';

const g1Setup = generateG1Setup(256)
const g2Setup = generateG2Setup(256)

const srsG1 = (number: number) => {
    return g1Setup.slice(0, number)
}

const srsG2 = (number: number) => {
    return g2Setup.slice(0, number)
}


/*
 * @return The coefficient to a polynomial which intersects the points (0,
 *         values[0]) ... (n, values[n]). Each value must be less than
 *         FIELD_SIZE. Likewise, each resulting coefficient will be less than
 *         FIELD_SIZE. This is because all operations in this function work in
 *         a finite field of prime order p = FIELD_SIZE. The output of this
 *         function can be fed into commit() to produce a KZG polynomial
 *         commitment to said polynomial.
 * @param values The values to interpolate.
 * @param p The field size. Defaults to the BabyJub field size.
 */
export const genCoefficients = (
    values: bigint[],
    p: bigint = PRIME_MODULUS,
): bigint[] => {
    // Check the inputs
    for (let value of values) {
        assert(typeof(value) === 'bigint')
        assert(value < p)
    }

    // Perform the interpolation
    const field = galois.createPrimeField(p, true)
    const x: bigint[] = []
    for (let i = 0; i < values.length; i ++) {
        x.push(BigInt(i))
    }
    const xVals = field.newVectorFrom(x)
    const yVals = field.newVectorFrom(values)
    const coefficients = field.interpolate(xVals, yVals).toValues()
 
    // Check the outputs
    for (let coefficient of coefficients) {
        assert(coefficient < p)
    }
    return coefficients
}



export const commit = (
    coefficients: bigint[],
): G1Point => {
    const srs = g1Setup.slice(0, coefficients.length)
    return polyCommit(coefficients, srs)
}

const polyCommit = (
    coefficients: bigint[],
    srs: G1Point[],
): G1Point => {
    let result = bls.G1.ProjectivePoint.ZERO
    for (let i = 0; i < coefficients.length; i ++) {
        let coeff = coefficients[i]

        const mulplyOp = srs[i].multiply(coeff);
        mulplyOp.assertValidity()
        
        result = result.add(mulplyOp)
    }

    return result
}

const G2PolyCommit = (
    coefficients: bigint[],
    srs: G2Point[],
): G2Point => {
    let result = bls.G2.ProjectivePoint.ZERO
    for (let i = 0; i < coefficients.length; i ++) {
        let coeff = coefficients[i]

        const mulplyOp = srs[i].multiply(coeff);
        mulplyOp.assertValidity()
        
        result = result.add(mulplyOp as any)
    }

    return result as any
}

/** 
 * @return A KZG commitment proof of evaluation at multiple points.
 * @param coefficients The coefficients of the polynomial associated with the
 *                     KZG commitment.
 * @param indices The x-values for the polynomial evaluation proof.
 * @param p The field size. Defaults to the BabyJub field size.
 */
export const genMultiProof = (
    coefficients: bigint[],
    indices: number[] | bigint[],
): G2Point => {
    assert(coefficients.length > indices.length)

    const field = galois.createPrimeField(PRIME_MODULUS)
    const poly = field.newVectorFrom(coefficients)

    const iPoly = genInterpolatingPoly(field, poly, indices)
    const zPoly = genZeroPoly(field, indices)
    const qPoly = field.divPolys(
        field.subPolys(poly, iPoly),
        zPoly,
    )

    const qPolyCoeffs = qPoly.toValues()

    const multiProof = G2PolyCommit(qPolyCoeffs, g2Setup.slice(0, coefficients.length))

    return multiProof as any
}

export const verifyMulti = (
    commitment: G1Point,
    proof: G2Point,
    indices: number[] | bigint[],
    values: bigint[],
) => {
    const field = galois.createPrimeField(PRIME_MODULUS)
    const xVals: bigint[] = []

    for (let i = 0; i < indices.length; i ++) {
        const index = BigInt(indices[i])
        xVals.push(index)
    }
    const iPoly = field.interpolate(
        field.newVectorFrom(xVals),
        field.newVectorFrom(values),
    )
    const zPoly = genZeroPoly(field, indices)

    // e(proof, commit(zPoly)) = e(commitment - commit(iPoly), g)



    const zCommit = commit(zPoly.toValues())
    const iCommit = commit(iPoly.toValues())

    const lhs = bls.pairing(
        zCommit,
        proof as any
    )

    const rhs = bls.pairing(
        commitment.subtract(iCommit),
        bls.G2.ProjectivePoint.BASE,
    )

    return bls.fields.Fp12.eql(lhs, rhs)
}



export const verify = (
    commitment: G1Point,
    proof: G2Point,
    index: number,
    value: bigint,
): boolean => {
    return verifyMulti(commitment, proof, [index], [value])
}


export const genProof = (
    coefficients: bigint[],
    index: number,
): G2Point => {
   return genMultiProof(coefficients, [index])
}
/**
 * Encodes input value to scalar on BLS finite field
 * @param data Uint8Array or string
 * @returns 
 */
export const encodeToScalar = (data: Hex): bigint => { 
    return bls.G1.normPrivateKeyToScalar(data)
}

