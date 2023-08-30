package rfc6238

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/mcaimi/go-hotp/rfc4226"
)

const (
  // default time step interval: 30 seconds
  TIMESTEP = 30
  // gmtime(0) or 1 Jan 1970. Unix Epoch
  EPOCH = 0
)

// totp token object
type TOTP struct {
 key []byte;
 timecounter int;
 timestep int;
 token_len int;
 is_base32 bool;
 algorithm string;
 computed_token uint32;
}

// generate a new totp object
func NewTotp(key []byte, timecounter int, timestep int, token_len int, is_base32 bool, algorithm string) TOTP {
  var t TOTP;

  // assign values
  t.key = key;
  t.timecounter = timecounter;
  t.timestep = timestep;
  t.token_len = token_len;
  t.is_base32 = is_base32;
  t.algorithm = algorithm;
  
  // return object
  return t;
}

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
func (v *TOTP) TotpToken() error {
  // google-authenticator style totp token
  // decode key from base32 encoded byte array
  if v.is_base32 {
    // compute padding information
    padlen := len(v.key) % 8;
    if padlen > 0 {
      padstring := fmt.Sprintf("%s", strings.Repeat("=", (8 - padlen)));
      // pad string as necessary
      v.key = append(v.key, []byte(padstring)...);
    }

    // decode the base32 input string
    output := make([]byte, base32.StdEncoding.DecodedLen(len(v.key)));
    _, err := base32.StdEncoding.Decode(output, []byte(v.key));
    if err != nil {
      return err;
    } else {
      v.key = output;
    }
  }

  // set up time counter
  var timevalue float64;
  if v.timecounter == -1 {
    timevalue = 12345678; // static value used for testing purposes
  } else if v.timecounter == 0 {
    now := time.Now();
    timevalue = math.Floor(float64(now.Unix() - int64(EPOCH)) / float64(v.timestep));
  } else {
    timevalue = math.Floor(float64(v.timecounter) / float64(v.timestep));
  }
 
  // generate TOTP value
  byteInterval := make([]byte, 8);
  binary.BigEndian.PutUint64(byteInterval, uint64(timevalue));
  h := rfc4226.NewHotp(v.key, byteInterval, v.token_len, v.algorithm);
  v.computed_token = h.HotpToken();

  // return computed totp value
  return nil;
}

// return a string representation of the totp token integer value
//
// totpToken: result of the TotpToken() function
// token_len: length of the computed Token
//
func (v *TOTP) TokenToString() string {
  // convert integer to string
  var totpString string;
  totpString = fmt.Sprintf("%d", v.computed_token);

  // pad as necessary
  ls := len(totpString);
  if ls < v.token_len {
    totpString = fmt.Sprintf("%s%s", strings.Repeat("0", (v.token_len - ls)), totpString);
  }
  return totpString;
}

