import { bls12_381 as bls } from "@noble/curves/bls12-381"
import { commit, genCoefficients, genMultiProof, genProof, verify, verifyMulti,  } from ".."
import { G1Point, PRIME_FIELD, PRIME_MODULUS, sha256 } from "../utils"
const testVals = [8, 23, 52, 105].map(BigInt)
const coefficients = genCoefficients(testVals, PRIME_MODULUS)


describe('kzg/apk proofs on bls12-381', () => { 
    
    describe('commit, prove, and verify the polynomial [8, 23, 52, 105]', () => { 
        it('compute small coefficientes', () => { 
            const values = [8, 23, 52, 105].map(BigInt)
            const c = genCoefficients(values, PRIME_MODULUS)

            
            for (let i = 0; i < c.length; i ++) {
                const expectedEval =
                    PRIME_FIELD.evalPolyAt(PRIME_FIELD.newVectorFrom(c), BigInt(i))
                expect(expectedEval).toEqual(values[i])
            }
        })
        it('compute large coefficientes', () => { 
            let values: bigint[] = []

            for(let x = 0; x < 5; x ++) {
                values.push(bls.G1.normPrivateKeyToScalar(sha256(`randomsalt-${x}`)))
            }
            const c = genCoefficients(values, PRIME_MODULUS)

            
            
            for (let i = 0; i < c.length; i ++) {
                const expectedEval =
                    PRIME_FIELD.evalPolyAt(PRIME_FIELD.newVectorFrom(c), BigInt(i))
                expect(expectedEval).toEqual(values[i])
            }
        })

        let commitment: G1Point
        let proof;
        let yVal
        let xVal = 2
        it('generate a KZG commitment', () => {
            commitment = commit(coefficients)
            
            // console.log(commitment.x, commitment.y)
            expect(commitment.x > 0 && commitment.y > 0).toBeTruthy()
        })

        it('generate a KZG proof', () => {
            yVal = PRIME_FIELD.evalPolyAt(PRIME_FIELD.newVectorFrom(coefficients), BigInt(xVal))
            proof = genProof(coefficients, xVal)
           //console.log('kzg proof', proof)
            //expect(proof.length === 3).toBeTruthy()
        })

        it('verify a KZG proof', () => {
            const isValid = verify(
                commitment,
                proof,
                xVal,
                yVal,
            )
            expect(isValid).toBeTruthy()

            
        })


        it('generate and verify a multi KZG proof', () => {
            const indexes = [1, 2]
            const mProof = genMultiProof(coefficients, indexes)
            const mProofValid = verifyMulti(commitment, mProof, indexes, indexes.map(e => testVals[e]))
            expect(mProofValid).toBeTruthy()
        })
    })
})