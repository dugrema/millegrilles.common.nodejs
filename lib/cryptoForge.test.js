const {genererCsrNavigateur} = require('./cryptoForge')
const {pki} = require('node-forge')
const fs = require('fs')

describe('Test generer CSR navigateur', ()=>{

  test('Generer CSR simple', async () => {
    console.debug("CSR")

    const nomUsager = 'testUser'
    const userId = 'mABCD1234'
    const cleNavigateur = pki.privateKeyFromPem(privateKey)
    const clePubliqueNavigateur = pki.setRsaPublicKey(cleNavigateur.n, cleNavigateur.e)

    const csr = await genererCsrNavigateur(nomUsager, clePubliqueNavigateur, cleNavigateur, {userId})

    console.debug("CSR :\n%s", csr)
    fs.writeFileSync('/tmp/csr.pem', csr)
  })

})

const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAubNGxG/ySxCfvSzx91HAnOUpN0HmluRbLvggw7S5ghDR3Fz1
08N9EKQBU/5rGK5fLQWD66BY5yOoQaQlKokdwUKlhDDI1pQuCqkGKGKw1CA6PacE
SslglL2gp6NafIDsrZUC6zHS86AgF2FJcaW/HDQCeSImakYH1MSFguVecv7+dS7T
zGX1725qe/XmyeUjGZGoGzzj7p9NEL/uDxsKEXDJBLjx3PXSAxhnm3e4Ca2ANa8o
5fZTR9jcHPBSg0V8xy7daZGscFufQ1q1D1qdX1lHIyDacTwjhxMiwhCS7Gh3dZgb
BdvQQnBmO/bL8sKtXOty/GX9R3CI8mo2KkLlXQIDAQABAoIBADZq79D+0SzoKTdh
pWKJZX1UtjhIKo+LSaFA+zD+k+ImlakS4ML2pX6r4OvBQZcQ+jkSRa9V5NePHm5l
8LI/TiXlJuXO+fvPnpJnJ7PL/++ZpheNCvfzfUb5LswRVaHokfLoGNvdVOkpwl23
l7MjFBbqstLWjBVWglL6Z/mMx5nA2XiqEVpjPLBJnEYRRocxrU3Zfio7S7ZvJjZW
Ty2RbRwO2NHlhx0jC5Jy7OlEevlo1JceRAfiSeQpsLQ7kL1wM5kbMAqQaSDLLKqO
0+hRaygBW3f3Qy+cIqqlt2xHEK071f7tFnT8SOpxVvdYpjx3E7Dntdk82CkHySvO
WbXmCsECgYEA7oXEP9YI8NwUhWK5oktWsKIfHXLCCj8SiKL0t9DwhyX9E7jLB5L2
cI2e3j81jHkEv1Zeng84yjtPlNzA8t+uHJuQ/tdFei+A1fBVgOpW2Mfi+OFhJHSh
ZHHekoGNPSgDF9uGAXcgzvDqj1pmE3+9qJnaQjciJ2PoShFIMOMsZk0CgYEAx06q
EWCATY5vY3TlxoVaGBiwKlcYTawnEK663NPn2mJC+dDFJv9qNcieqzPMEHryjCqu
/unMPb4YeC+IT5ArpKseokioT0vf2HviEsPBdXkoEQB2eX9du2FJfYzfkKC7Vayc
hnz6goqw8VTtVCCR+tTbbzi+5DhWZw+iQqUiI1ECgYBJrLHQkfkTBLel97elJKYz
SvBXdUHwTkkYQVVbjcMty5MfS14TCdbrLyNaPKX6rMrFmxUAt2zwMl/DeGh03Jh4
J6kivjWspw2hh2mxtzB6J0u5WkxaKVhMoUuBb1jEAh7qeJkszLIqmYmqG98ZuMRJ
VrRu7X60MgznC+2DhDgLpQKBgDvFRY9sh02694C2H+qHN1uem8Y21F0G0bhZDkUH
b7K4YSmWCGoHkwyKG7twDzSqCm8qpcxgxRWHGsOATbq+m7gIcWltrLwLHxhHHqdN
+YiHSxK+Nsl8/tkg9e8m/izbZxLsbwyOEnpvqVzWgU4Hbn/wsdYLCIRcuNyzfY/L
Ag/hAoGAC7kJ1kE4eRPVsKzRqKbZFgnZTZotNoq0NCls7X+P8AAK3k4lBXdPqnmO
SbFB28SYWTyoW0SDar+HEEKYXoJoh6SQI2klaa1sm7GZo9GJrpaIltXVtr19U45Y
BNR5wxn42t0uGQzdlDreX0KUvhIun2A6lKYFrJ3r6zb2uxV+Jq0=
-----END RSA PRIVATE KEY-----
`
