package rfc6238

import (
  "github.com/mcaimi/go-hmac/rfc2104"
)

// Google Auth compliant TOTP generation function
//
// key: array of base32-encoded key bytes
// length: length of the resulting totp token
//
func GoogleAuth(key []byte, length int) string {
  var tk uint32;
  var err error;

  // compute totp token with Google Auth compatibility
  // key is base32 encoded
  tk, err = TotpToken(key, 0, TIMESTEP, length, true, rfc2104.SHA1Hmac);
  if err != nil {
    return "";
  }

  // return string representation of the totp token
  return TokenToString(tk, length);
}

// RFC6238 compliant TOTP generation function
//
// key: array of key bytes
// length: length of the resulting totp token
// timestep: period of validity of the computed token (seconds)
//
func TOTP(key []byte, length int, timestep int) string {
  var tk uint32;
  var err error;

  // compute totp token as per rfc
  tk, err = TotpToken(key, 0, timestep, length, false, rfc2104.SHA1Hmac);
  if err != nil {
    return "";
  }

  // return string representation of the totp token
  return TokenToString(tk, length);
}
