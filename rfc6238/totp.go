package rfc6238

// Google Auth compliant TOTP generation function
//
// key: array of base32-encoded key bytes
// length: length of the resulting totp token
//
func GoogleAuth(key []byte, length int) string {
  var err error;

  // compute totp token with Google Auth compatibility
  // key is base32 encoded
  t := NewTotp(key, 0, TIMESTEP, length, true, "sha1");
  err = t.TotpToken();
  if err != nil {
    return "";
  }

  // return string representation of the totp token
  return t.TokenToString();
}

// RFC6238 compliant TOTP generation function
//
// key: array of key bytes
// length: length of the resulting totp token
// timestep: period of validity of the computed token (seconds)
//
func Totp(key []byte, length int, timestep int, base32 bool, algorithm string) string {
  var err error;

  // compute totp token as per rfc
  t := NewTotp(key, 0, timestep, length, base32, algorithm);
  err = t.TotpToken();
  if err != nil {
    return "";
  }

  // return string representation of the totp token
  return t.TokenToString();
}
