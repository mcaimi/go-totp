package rfc6238

import (
  "fmt"
  "strings"
  "math"
  "time"
  "encoding/base32"
  "encoding/binary"
  "github.com/mcaimi/go-hotp/rfc4226"
)

const (
  // default time step interval: 30 seconds
  TIMESTEP = 30
  // gmtime(0) or 1 Jan 1970. Unix Epoch
  EPOCH = 0
)

// normalize input string
// remove all whitespaces and convert the string into a byte array
//
// inputString: string to normalize and convert
//
func normalize(inputString string) []byte {
  // remove any whitespaces
  ns := strings.ReplaceAll(inputString, " ", "");

  // return decoded value
  return []byte(ns);
}

// generic TOTP compute function
// computes the TOTP token as per RFC 6238.
// returns an unsigned 32-bit integer representation of the TOTP token that can be used as is or otherwise
// converted into another formant (e.g. string)
//
// key: byte array of the secret key to use during computation
// timecounter: point in time from epoch for which you wan to compute the TOTP (default is time.Now())
// timestep: TOTP token period. default is 30 seconds (google-auth compatibility)
// token_len: length of the TOTP token in bytes (default is 6)
// is_base32: specifies whether the key array is base32 encoded or not (google-auth compatibility)
// digestFunc: HMAC function to use during computation
// 
func TotpToken(key []byte, timecounter int, timestep int, token_len int, is_base32 bool, digestFunc func([]byte, []byte) []byte) (uint32, error) {
  // google-authenticator style totp token
  // decode key from base32 encoded byte array
  if is_base32 {
    // compute padding information
    padlen := len(key) % 8;
    if padlen > 0 {
      padstring := fmt.Sprintf("%s", strings.Repeat("=", (8 - padlen)));
      // pad string as necessary
      key = append(key, []byte(padstring)...);
    }

    // decode the base32 input string
    output := make([]byte, base32.StdEncoding.DecodedLen(len(key)));
    _, err := base32.StdEncoding.Decode(output, []byte(key));
    if err != nil {
      return 0, err;
    } else {
      key = output;
    }
  }

  // set up time counter
  var timevalue float64;
  if timecounter == -1 {
    timevalue = 12345678; // static value used for testing purposes
  } else if timecounter == 0 {
    now := time.Now();
    timevalue = math.Floor(float64(now.Unix() - int64(EPOCH)) / float64(timestep));
  } else {
    timevalue = math.Floor(float64(timecounter) / float64(timestep));
  }
 
  // generate TOTP value
  var totpToken uint32;
  byteInterval := make([]byte, 8);
  binary.BigEndian.PutUint64(byteInterval, uint64(timevalue));
  totpToken = rfc4226.HotpToken(key, byteInterval, token_len, digestFunc);

  // return computed totp value
  return totpToken, nil;
}

// return a string representation of the totp token integer value
//
// totpToken: result of the TotpToken() function
// token_len: length of the computed Token
//
func TokenToString(totpToken uint32, token_len int) string {
  // convert integer to string
  var totpString string;
  totpString = fmt.Sprintf("%d", totpToken);

  // pad as necessary
  ls := len(totpString);
  if ls < token_len {
    totpString = fmt.Sprintf("%s%s", strings.Repeat("0", (token_len - ls)), totpString);
  }
  return totpString;
}

