// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

//go:build ignore

// gen_tokens generates hardcoded JWT tokens for example tests.
// Run with: go run gen_tokens.go
package main

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func main() {
	const webkeyJSON = `{"kty":"RSA","kid":"1","alg":"PS512","n":"x6JoG8t2Li68JSwPwnh51TvHYFf3z72tQ3wmJG3VosU6MdJF0gSTCIwflOJ38OWE6hYtN1WAeyBy2CYdnXd1QZzkK_apGK4M7hsNA9jCTg8NOZjLPL0ww1jp7313Skla7mbm90uNdg4TUNp2n_r-sCYywI-9cfSlhzLSksxKK_BRdzy6xW20daAcI-mErQXIcvdYIguunJk_uTb8kJedsWMcQ4Mb57QujUok2Z2YabWyb9Fi1_StixXJvd_WEu93SHNMORB0u6ymnO3aZJdATLdhtcP-qsVicQhffpqVazmZQPf7K-7n4I5vJE4g9XXzZ2dSKSp3Ewe_nna_2kvbCw","e":"AQAB","d":"sl3F_QeF2O-CxQegMRYpbL6Tfd47GM6VDxXOkn_cACmNvFPudB4ILPvdf830cjTv06Lq1WS8fcZZNgygK0A_cNc3-pvRK67e-KMMtuIlgU7rdwmwlN1Iw1Ee-w6z1ZjC-PzR4iQMCW28DmKS2I-OnV4TvH7xOe7nMmvTPrvujV__YKfUxvAWXJG7_wtaJBGplezn5nNsKG2Ot9h0mhMdYUgGC36wLxo3Q5d4m79EXQYdhm89EfxogwvMmHRes5PNpHRuDZRHGAI4RZi2KvgmqF07e1Qdq4TqbQnY5pCYrdjqvEFFjGC6jTE-ak_b21FcSVy-9aZHyf04U4g5-cIUEQ","p":"7AaicFryJCHRekdSkx8tfPxaSiyEuN8jhP9cLqs4rLkIbrSHmanPhjnLe-Tlh3icQ8hPoy6WC8ktLwsrzbfGIh4U_zgAfvtD1Y_lZM-YSWZsxqlrGiI5do11iVzzoy4a1XdkgOjHQz9y6J-uoA9jY8ILG7VaEZQnaYwWZV3cspk","q":"2Ide9hlwthXJQJYqI0mibM5BiGBxJ4CafPmF1DYNXggBCczZ6ERGReNTGM_AEhy5mvLXUH6uBSOJlfHTYzx49C1GgIO3hEWVEGAKAytVRL6RfAkVSOXMQUp-HjXKpGg_Nx1SJxQf3rulbW8HXO4KqIlloyIXpPQSK7jB8A4hJUM","dp":"1nmc6F4sRNsaQHRJO_mL21RxM4_KtzfFThjCCoJ6iLHHUNnpkp_1PTKNjrLMRFM8JHgErfMqU-FmlqYfEtvZRq1xRQ39nWX0GT-eIwJljuVtGQVglqnc77bRxJXbqz-9EJdik6VzVM92Op7IDxiMp1zvvSkJhInNWqL6wvgNEZk","dq":"dlHizlAwiw90ndpwxD-khhhfLwqkSpW31br0KnYu78cn6hcKrCVC0UXbTp-XsU4JDmbMyauvpBc7Q7iVbpDI94UWFXvkeF8diYkxb3HqclpAXasI-oC4EKWILTHvvc9JW_Clx7zzfV7Ekvws5dcd8-LAq1gh232TwFiBgY_3BMk","qi":"E1k_9W3odXgcmIP2PCJztE7hB7jeuAL1ElAY88VJBBPY670uwOEjKL2VfQuz9q9IjzLAvcgf7vS9blw2RHP_XqHqSOlJWGwvMQTF0Q8zLknCgKt8q7HQQNWIJcBZ8qdUVn02-qf4E3tgZ3JHaHNs8imA_L-__WoUmzC4z5jH_lM"}`

	webKeyPair, err := jwk.ParseKey([]byte(webkeyJSON))
	if err != nil {
		panic(err)
	}

	sign := func(claims any) string {
		payload, _ := json.Marshal(claims)
		signed, _ := jws.Sign(payload, jws.WithKey(jwa.RS256(), webKeyPair))
		return string(signed)
	}

	// accessToken example claims
	accessClaims := map[string]interface{}{
		"aud": []string{"unit", "test"},
		"bar": map[string]interface{}{
			"count": 22,
			"tags":  []string{"some", "tags"},
		},
		"exp": 4802234675,
		"foo": "Hello, World!",
		"iat": 1678097014,
		"iss": "local.com",
		"jti": "9876",
		"nbf": 1678097014,
		"sub": "tim@local.com",
	}
	fmt.Println("=== accessToken ===")
	fmt.Println(sign(accessClaims))

	// idToken example claims
	idClaims := map[string]interface{}{
		"acr":       "something",
		"amr":       []string{"foo", "bar"},
		"at_hash":   "2dzbm_vIxy-7eRtqUIGPPw",
		"aud":       []string{"unit", "test", "555666"},
		"auth_time": 1678100961,
		"azp":       "555666",
		"bar": map[string]interface{}{
			"count": 22,
			"tags":  []string{"some", "tags"},
		},
		"client_id": "555666",
		"exp":       4802238682,
		"foo":       "Hello, World!",
		"iat":       1678101021,
		"iss":       "local.com",
		"jti":       "9876",
		"nbf":       1678101021,
		"nonce":     "12345",
		"sub":       "tim@local.com",
	}
	fmt.Println("=== idToken ===")
	fmt.Println(sign(idClaims))

	// second accessToken for rp test
	accessClaims2 := map[string]interface{}{
		"aud": []string{"unit", "test"},
		"bar": map[string]interface{}{
			"count": 22,
			"tags":  []string{"some", "tags"},
		},
		"exp": 4802238682,
		"foo": "Hello, World!",
		"iat": 1678101021,
		"iss": "local.com",
		"jti": "9876",
		"nbf": 1678101021,
		"sub": "tim@local.com",
	}
	fmt.Println("=== rp_accessToken ===")
	fmt.Println(sign(accessClaims2))
}
