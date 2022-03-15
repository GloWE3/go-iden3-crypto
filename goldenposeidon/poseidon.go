package poseidon

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/ffg"
)

const spongeChunkSize = 31
const spongeInputs = 16

func zero() *ffg.Element {
	return ffg.NewElement()
}

// exp7 performs x^7 mod p
func exp7(a *ffg.Element) {
	a.Exp(*a, big.NewInt(7)) //nolint:gomnd
}

// exp7state perform exp7 for whole state
func exp7state(state []*ffg.Element) {
	for i := 0; i < len(state); i++ {
		exp7(state[i])
	}
}

// ark computes Add-Round Key, from the paper https://eprint.iacr.org/2019/458.pdf
func ark(state []*ffg.Element, it int) {
	for i := 0; i < len(state); i++ {
		state[i].Add(state[i], C[it+i])
	}
}

// mix returns [[matrix]] * [vector]
func mix(state []*ffg.Element) []*ffg.Element {
	mul := zero()
	newState := make([]*ffg.Element, mLen)
	for i := 0; i < mLen; i++ {
		newState[i] = zero()
	}
	for i := 0; i < mLen; i++ {
		newState[i].SetUint64(0)
		for j := 0; j < mLen; j++ {
			mul.Mul(M[i][j], state[j])
			newState[i].Add(newState[i], mul)
		}
	}
	return newState
}

// Hash computes the Poseidon hash for the given inputs
func Hash(inpBI [NROUNDSF]uint64, capBI [CAPLEN]uint64) ([CAPLEN]uint64, error) {
	state := make([]*ffg.Element, mLen)
	for i := 0; i < NROUNDSF; i++ {
		state[i] = ffg.NewElement().SetUint64(inpBI[i])
	}
	for i := 0; i < CAPLEN; i++ {
		state[i+NROUNDSF] = ffg.NewElement().SetUint64(capBI[i])
	}

	for r := 0; r < NROUNDSF+NROUNDSP; r++ {
		ark(state, r*mLen)

		if r < NROUNDSF/2 || r >= NROUNDSF/2+NROUNDSP {
			exp7state(state)
		} else {
			exp7(state[0])
		}

		state = mix(state)
	}

	return [CAPLEN]uint64{state[0].ToUint64Regular(), state[1].ToUint64Regular(), state[2].ToUint64Regular(), state[3].ToUint64Regular()}, nil
}
