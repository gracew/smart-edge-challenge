package signature

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestBasic(t *testing.T) {
	encodedKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4LrwBV7X+ri8hqnutTgJvv4AGFavzR/mtHkJ1Q00DhCYkEPz
sZaEZbdy9WoubN/zn4IanclYCtUj5Jw8ztkR2X2m47Uc1ugrwH9wdf3iI0wu8KZS
+FURtRtuzoUZxkLxMUaz53VCs+jPzHMy3PfGN0YR9CL6hW3pE4GoL1xjNnJljpGK
133Tjyxysyt/8HHDgS+EORLHK2qItgo6oHhhi5/kIkRZC1ZrlDuMyz7IwhafmUdG
5bhSTR6/XdeieuEKiaxHS6p7lYRxgXihQ3+Lae+UbjV0k7VqpuXwTXYLT/6cjFrm
RO7XEko3LbCSeLH7pkhzJphsEKT1dkPJNq8wawIDAQABAoIBABR6dGzI272JIATV
b18sIBc7Zh7Rp2t1wLwpW3ACp/+wG3bp+kbwhFgQg3VBm8FoFvcuD+bY9iDmk0K9
yfy/YxUCkjalxl7/AR2lf0YBQJ4ezxg2z9C5T8fFHC/NiS+74eavnq00zkM+r9Dd
noDsQy++PtyUY2fNQDP62KyYKqJHVpVHba8sgkQtJSHdgJC+uEjA8eC3NRu58KzD
6SW13LJxumnqiFXoMfHSSTLzh8uUZQ8dAlp/++LeqqX/9nZW8aF50zuQCzdu9hhK
XUyhZfaU7hAeeVW3KRAnkckw+g8PoKERONWY/mg+B7vQ9Ekrnk6EuFdtIJmFHhhK
fWf55EECgYEA4V4A9j72lyiUOVDPHUrWVWdVrr56wVkKv6saZ3x9MmCj4s+y7ADS
LkgLFWEVi0Y3UuTuHjm2doVv2TQfYfg8aG2JYiMufrZ3DFQTZPiakG3r6IhFP3kJ
bjo9qZkkIoa2nhakvy+VVOZYVDXM+rU0NnG3Q7WUlsv0h+nRlfJTI6kCgYEA/0bE
7BqT3N1GYN0wjp4X3vLgELw4GDbk/3QFWPyWFkrF9NIZTXjrIDu3955tXcH+eq2+
btKol+2jsEs3Hh5GU+ctJx0G7aIWlsNoxKbbRF+DNxWVRIcwaSnt+uInltLPozWs
z9t8qLLe2tSJkX/v/VrYkHxE0WHvtzgPMO6n//MCgYEAon4Z6XKqb4C1psHKI8+y
zG8uS0lRzxi5dEsVRapvxqQBZmblFd7drLsLKsYON5ZQC3e+7JImKjy50X0QZ54J
SC46UUUWoAxFt+Di/vl00FBBOS8P5t0JXK2niiI9+JrzDvc6oBLZ9BYFd+o2uklu
tRa20Z4Z3cR+soR3Nks7gMkCgYEAsCR/2r6YCo1wc4QMbkwuAnuqGkIVnre6GX5P
9lALrAQaRcz3ApsN+qbaUPUzV791PedHAKdBB9xE129+77xKILjiUhvYXP48AfmC
ADd2Et6o5shwv+FciSQSfsuwL4T1GxP9U0uK38jUt0ByUEBsM3CNAF2PCr8+Ljlz
WftDVvsCgYApkJgIkj6IPmM2qWR17w6rF+sUNkem6I+4F4QJ4lEfNgPOerEcRoU2
ErqiBgRjkHJHzMh4EJ+npZMIVowwLkGm519mRQJo2mIjMEib6Uay9Tlh2vLxmg1Q
m44D7PKEfVC2oRRxtessjKkQ27ppF6A5p50EDy9aiDmYdkLvkmsd6w==
-----END RSA PRIVATE KEY-----
`
	block, _ := pem.Decode([]byte(encodedKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fail()
	}

	message := "theAnswerIs42"
	actual := SignInput(message, key)
	expected := SignedIdentifier{
		Message:   message,
		Signature: "LY1qxOwibS+EhyKRR3M8GkAp+ZV0fi46I3t2+/lBMNiol/xCfvkkg9pENpAV+pLv7MdgTt2lXJzDx6nqdaMAAazrWC90UsXVPqe4dDujUJzRJzwlT4yC37kUBdsYXn5c4BEn1qbjZDHhgMbpvd4g6uOPGh+k1chdJLhmRtc82+DyXTCS7BuJaiXD9x9mS8kzn4p9yDs4o43CM95DC4+Nnc9qKowMlyQBJs6rTMxrETudZ3ehHt9W/MVZhfiCVcIpgRxaGh5njaRpGHUk9C4VkVO9SrEDIxdeYE1a7TlLbyrS5LGyA9SYxKwlQWkybu29dU3T2PGtBo9NRh/gDNPLMA==",
		Pubkey: `-----BEGIN PUBLIC KEY-----
MIIBCgKCAQEA4LrwBV7X+ri8hqnutTgJvv4AGFavzR/mtHkJ1Q00DhCYkEPzsZaE
Zbdy9WoubN/zn4IanclYCtUj5Jw8ztkR2X2m47Uc1ugrwH9wdf3iI0wu8KZS+FUR
tRtuzoUZxkLxMUaz53VCs+jPzHMy3PfGN0YR9CL6hW3pE4GoL1xjNnJljpGK133T
jyxysyt/8HHDgS+EORLHK2qItgo6oHhhi5/kIkRZC1ZrlDuMyz7IwhafmUdG5bhS
TR6/XdeieuEKiaxHS6p7lYRxgXihQ3+Lae+UbjV0k7VqpuXwTXYLT/6cjFrmRO7X
Eko3LbCSeLH7pkhzJphsEKT1dkPJNq8wawIDAQAB
-----END PUBLIC KEY-----
`,
	}
	if expected != actual {
		t.Fail()
	}
}
