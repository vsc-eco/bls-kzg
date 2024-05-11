import * as assert from 'assert'
import * as galois from '@guildofweavers/galois'



/*
 * @return A the coefficients to the quotient polynomial used to generate a
 *         KZG proof.
 * @param coefficients The coefficients of the polynomial.
 * @param xVal The x-value for the polynomial evaluation proof.
 * @param p The field size. Defaults to the BabyJub field size.
 */
export const genQuotientPolynomial = (
    field: galois.FiniteField,
    coefficients: bigint[],
    xVal: bigint,
): bigint[] => {
    const poly = field.newVectorFrom(coefficients)

    const yVal = field.evalPolyAt(poly, xVal)
    const y = field.newVectorFrom([yVal])

    const x = field.newVectorFrom([0, 1].map(BigInt))

    const z = field.newVectorFrom([xVal].map(BigInt))

    return field.divPolys(
        field.subPolys(poly, y),
        field.subPolys(x, z),
    ).toValues()
}

export const genZeroPoly = (
    field: galois.FiniteField,
    indices: number[] | bigint[],
): galois.Vector => {
    let zPoly = field.newVectorFrom([
        // @ts-ignore
        field.mod(BigInt(-1) * BigInt(indices[0])),
        BigInt(1),
    ])

    for (let i = 1; i < indices.length; i ++) {
        zPoly = field.mulPolys(
            zPoly,
            field.newVectorFrom([
                BigInt(-1) * BigInt(indices[i]),
                BigInt(1),
            ]),
        )
    }

    return zPoly
}

export const genInterpolatingPoly = (
    field: galois.FiniteField,
    poly: galois.Vector,
    indices: number[] | bigint[],
): galois.Vector => {
    const x: bigint[] = []
    const values: bigint[] = []

    for (let i = 0; i < indices.length; i ++) {
        const index = BigInt(indices[i])
        const yVal = field.evalPolyAt(poly, index)
        x.push(index)
        values.push(yVal)
    }

    const iPoly = field.interpolate(
        field.newVectorFrom(x),
        field.newVectorFrom(values),
    )

    return iPoly
}