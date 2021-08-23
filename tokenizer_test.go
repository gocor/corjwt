package corjwt

import (
	"testing"

	"github.com/dgrijalva/jwt-go"
)

type testClaims struct {
	jwt.StandardClaims

	UserID string `json:"user_id"`
}

func TestRSATokenization(t *testing.T) {
	privateKey, err := PrivateRSAFromPemFile("test/test.rsa")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := PublicRSAFromPemFile("test/test.rsa.pub")
	if err != nil {
		t.Fatal(err)
	}

	sut := NewTokenizer(
		jwt.SigningMethodRS256,
		privateKey, publicKey, &testClaims{})

	c := testClaims{
		StandardClaims: jwt.StandardClaims{
			Id: "SomeID",
		},
		UserID: "MyUserID",
	}

	tokenString, err := sut.NewWithClaims(&c)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokenString) == 0 {
		t.Fatal("tokenString is not valid")
	}

	token, err := sut.ParseWithClaims(tokenString)
	if err != nil {
		t.Fatal(err)
	}
	if !token.Valid {
		t.Fatal("Token is not valid")
	}

	retClaims, ok := token.Claims.(*testClaims)
	if !ok {
		t.Fatal("Not able to cast to *testClaims")
	}
	if retClaims.UserID != c.UserID {
		t.Fatal("UserIDs do not match")
	}
}
