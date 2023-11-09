package poseidon

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/n8wb/go-iden3-crypto/ff"
	"github.com/stretchr/testify/require"
)

func hex2bytes(hexStr string) []byte {
	b, _ := hex.DecodeString(hexStr)
	return b
}

var (
	test1 = hex2bytes("0932be6bab062a99339dbc654f2880529aea654d08d6f480a26e027a7f6cb89d")
	test2 = hex2bytes("16408961fcbf436a08c1a3fae4756298d7311eeff0d92c6fda0d280f51314821")
	test3 = hex2bytes("01dade9c9c18b47f75dbe365636e37e38a1edba0d764b4e4937a8e6084d47cc9")
	test4 = hex2bytes("229dcdd21826db7476f786070d6f01f70bad25eb87642816e289ce65caf457a2")
)

func Test_stateReduce(t *testing.T) {
	stateStrs := []string{
		"15757424935574807375738855899726289747887771996092261017827722666909347781407",
		"13480061881289094778636092474716199813341351065087415026247249797108547636601",
		"8710895786925397077695468387823539552726750935886004745564064126551011697061",
		"19851758224339694721021048027525717827089036056317537080583722508089238736649",
		"12482759189806118238496495884796110363279889031309513470588070080546620957074",
	}
	state := make([]*ff.Element, 5)
	for i, s := range stateStrs {
		state[i] = ff.NewElement().SetString(s)
		require.Equal(t, state[i].String(), s)
	}
	tt := 5
	outputState := make([]*ff.Element, 5)
	for i := range state {
		outputState[i] = stateReduce(state, tt, i)
	}
	require.Equal(t, outputState[0].String(), "15685883464882498801027107262564604067876039711850706881845119297383563192249")
	require.Equal(t, outputState[1].String(), "2900266235757970516887992992104841652729680883108337807793061354919794973260")
	require.Equal(t, outputState[2].String(), "5841166528159537187948968497656342365963315413468220480465282299820112774836")
	require.Equal(t, outputState[3].String(), "6755980305578931490638928234088522080379019875325797445313103032557968821111")
	require.Equal(t, outputState[4].String(), "2581044636281275518567052420634436017065180578764179169194299138890360821160")

}

func Test_Poseidon2(t *testing.T) {
	result, err := Poseidon2([]*big.Int{
		new(big.Int).SetBytes(test1),
		new(big.Int).SetBytes(test2),
		new(big.Int).SetBytes(test3),
		new(big.Int).SetBytes(test4),
	})
	require.NoError(t, err)
	require.Equal(t, result.Text(16), "206a71a94faf9170deb4e645e072c072f346915f0f6de5781479abae9d75477a")
}
