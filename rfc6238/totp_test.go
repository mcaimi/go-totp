package rfc6238

import (
  "testing"
  "github.com/mcaimi/go-hmac/rfc2104"
)

const (
  KEY = "ORSXG5A="
  RESULT_RFC = "285265"
  RESULT_GOOGLE = "042328"
  TEST_TOKEN_LEN = 6
)

func TestRFC(t *testing.T) {
  var keyBytes []byte;
  var testToken string;

  keyBytes = normalize(KEY);
  t.Logf("Key Bytes: %q\n", keyBytes);

  intToken, err := TotpToken(keyBytes, -1, 60, TEST_TOKEN_LEN, false, rfc2104.SHA1Hmac);
  if err != nil {
    t.Fail();
  }
  testToken = TokenToString(intToken, TEST_TOKEN_LEN);

  t.Logf("Computed TOTP Token (RFC): %s\n", testToken);

  if !(testToken == RESULT_RFC) {
    t.Logf("Test Failed: TOTP: %s, REFERENCE: %s\n", testToken, RESULT_RFC);
    t.Fail();
  }
}

func TestGoogle(t *testing.T) {
  var keyBytes []byte;
  var testToken string;

  keyBytes = normalize(KEY);
  t.Logf("Key Bytes: %q\n", keyBytes);

  intToken, err := TotpToken(keyBytes, -1, TIMESTEP, TEST_TOKEN_LEN, true, rfc2104.SHA1Hmac);
  if err != nil {
    t.Fail();
  }
  testToken = TokenToString(intToken, TEST_TOKEN_LEN);
  t.Logf("Computed TOTP Token (GOOGLE): %s\n", testToken);

  if !(testToken == RESULT_GOOGLE) {
    t.Logf("Test Failed: TOTP: %s, REFERENCE: %s\n", testToken, RESULT_GOOGLE);
    t.Fail();
  }
}
