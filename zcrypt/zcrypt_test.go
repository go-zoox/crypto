package zcrypt

import (
	"testing"
)

func TestBcryptGenerate(t *testing.T) {
	password := "password"

	for i := 0; i < 10; i++ {
		hash := Generate(password)

		// fmt.Println(hash)

		if !Compare(password, hash) {
			t.Fatal("password and hash do not match")
		}
	}
}

func TestBcryptCompare(t *testing.T) {
	password := "password"
	hashs := []string{
		"1663152388887.jyathYgzTX.39f39f5630834551b3da81eea1dc2f8065013045da6fbd19645ae9f3ab2c8eb2",
		"1663152388887.IunOUCgzQb.621acf12f9e991169090098e53a68705edb4a41198252da44ba70fc28cfa2620",
		"1663152388887.wOoRzdDOmm.bcb4e062fc5c859d33a26c93f6a08a6bb85d8452af46e53e062d7c6d8cf6595f",
		"1663152388887.bpDRBhFbJf.2731fc90d5b9d9f11ec0dff04fe1b2107b64f29c50dd47b1616c3912dfb99bb4",
		"1663152388887.zNyokZYYbw.0f040d8bcedf59e40f6c8cb7475df3d4a2adcae9cb2b5555fa82318ea31defd4",
		"1663152388887.VZIPvOekIw.ca472704a797f72fdec03e428a71cfc6570856cbd6e4dd05b63d5ab52edda0ab",
		"1663152388887.PxADEhvNjx.5647cf002f3c3236a515d435a0fdf534f7efbe06140f864b3771c69bbd53d18f",
		"1663152388887.hTNuYtYqMV.795f1a7353b68b63da9af7529c3c2fd46943f44460bf7c82bf671c60347be7c6",
		"1663152388887.uUGiNBiThm.22d8772e77f6bef1264361f71d7def63eca777d6f304a8c29541c332ab6e9e5a",
		"1663152388887.BUfmGBtXlr.14a86df8d63d99271d213411671b64da3ef3fffd180af1667016d3849d6af2af",
	}

	for _, hash := range hashs {
		if !Compare(password, hash) {
			t.Fatal("password and hash do not match")
		}
	}

	if Compare(password, "xxx") {
		t.Fatal("password and hash should not match")
	}
}
