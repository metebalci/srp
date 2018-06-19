package srp

import (
  "crypto/sha1"
  "encoding/hex"
  "math/big"
  "testing"
)

type TestHelper struct {
  a string
  b string
  v string
  s string
}

const (

  rfc5054_I = "alice"
  rfc5054_p = "password123"
  rfc5054_s = "BEB25379D1A8581EB5A727673A2441EE"
  rfc5054_N = rfc5054_1024_N
  rfc5054_g = rfc5054_1024_g
  rfc5054_k = "7556AA045AEF2CDD07ABAF0F665C3E818913186F"
  rfc5054_x = "94B7555AABE9127CC58CCF4993DB6CF84D16C124"
  rfc5054_v = "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB"
  rfc5054_a = "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393"
  rfc5054_b = "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20"
  rfc5054_A = "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B"
  rfc5054_B = "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58"
  rfc5054_u = "CE38B9593487DA98554ED47D70A7AE5F462EF019"
  rfc5054_premaster_secret = "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A"

)

func (testHelper *TestHelper) srp_a() []byte {
  a, _ := hex.DecodeString(testHelper.a)
  return a
}

func (testHelper *TestHelper) srp_b() []byte {
  b, _ := hex.DecodeString(testHelper.b)
  return b
}

func (testHelper  *TestHelper) srp_v(I string) []byte {
  v, _ := hex.DecodeString(testHelper.v)
  return v
}

func (testHelper  *TestHelper) srp_s(I string) []byte {
  s, _ := hex.DecodeString(testHelper.s)
  return s
}

func hex2i(s string) *big.Int {
  i, _ := new(big.Int).SetString(s, 16)
  return i
}

func TestRfc5054(t *testing.T) {

  testHelper := &TestHelper{rfc5054_a, rfc5054_b, rfc5054_v, rfc5054_s}

  I := rfc5054_I
  p := rfc5054_p

  srp := NewSrp(hex2i(rfc5054_N), hex2i(rfc5054_g), hex2i(rfc5054_k), sha1.New(), testHelper, testHelper)

  // user enters I and p
  a, A, err := srp.SrpXchg1_User()
  if err != nil {
    t.Fatalf("Srp1 err: %v", err)
  }
  t.Logf("a: %v\n", a)
  t.Logf("A: %v\n", A)
  if A.Cmp(hex2i(rfc5054_A)) != 0 {
    t.Fatal("A is incorrect!")
  }

  // user to host => I, A
  s, B, u, host_S, host_K, err := srp.SrpXchg2_Host(I, A)
  if err != nil {
    t.Fatalf("Srp2 err: %v", err)
  }
  t.Logf("s: %v\n", s)
  t.Logf("B: %v\n", B)
  t.Logf("u: %v\n", u)
  t.Logf("host_S: %v\n", host_S)
  t.Logf("host_K: %v\n", host_K)
  if B.Cmp(hex2i(rfc5054_B)) != 0 {
    t.Fatal("B is incorrect!")
  }
  if u.Cmp(hex2i(rfc5054_u)) != 0 {
    t.Fatalf("u is incorrect!")
  }
  if host_S.Cmp(hex2i(rfc5054_premaster_secret)) != 0 {
    t.Fatalf("host_S is incorrect!")
  }

  // host to user => s, B
  user_S, user_K, user_M, err := srp.SrpXchg3_User(I, p, s, A, B, a)
  if err != nil {
    t.Fatalf("Srp3 err: %v", err)
  }
  t.Logf("user_S: %v\n", user_S)
  t.Logf("user_K: %v\n", user_K)
  t.Logf("user_M: %v\n", user_M)
  if user_S.Cmp(hex2i(rfc5054_premaster_secret)) != 0 {
    t.Fatalf("user_S is incorrect!")
  }

  // user to host => user_M
  host_HAMK, err := srp.SrpXchg4_Host(I, s, A, B, host_K, user_M)
  if err != nil {
    t.Fatalf("Srp4 err: %v", err)
  }
  t.Logf("host_HAMK: %v", host_HAMK)

  // host to user => NOTHING
  err = srp.SrpXchg5_User(A, user_K, user_M, host_HAMK)
  if err != nil {
    t.Fatalf("Srp5 err: %v", err)
  }


}
