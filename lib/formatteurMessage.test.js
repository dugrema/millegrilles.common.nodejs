const {hacherMessage, SignateurMessage, FormatteurMessage} = require('./formatteurMessage')

const HACHAGE_MESSAGE_1 = 'mEiC7ijJQr6Bbj8m/ggWWKzt0HrTfVK29c630658ep9OR1Q'
const MESSAGE_1 = {valeur: 1, boolbool: true}

const HACHAGE_MESSAGE_2 = 'mEiCTYQUmipCIDGauFwcwtEJW7hJUhrrpqGHUcNZHj3S+oA'
const MESSAGE_2 = {
  'texte': 'Du texte',
  'int': 1234,
  'float': 5678.12,
  'float zero': 1234.0,
  'date': new Date('2021-02-20T13:00Z').getTime()/1000,
  'dict': {'valeur': 'davantage de contenu'},
  'texte_accents': 'ÀÉËÊÈÇÏÎÔÛŨÙàéëèçïîôù',
  'texte_chars': '¤{}[]¬~`°|/\'\"\n\\'
}

const PEM_CERT = `
-----BEGIN CERTIFICATE-----
MIIEbDCCA1SgAwIBAgIUd8jlVh+5i4blQjkMSEbOAx42Xh4wDQYJKoZIhvcNAQEL
BQAwfjEtMCsGA1UEAxMkYjBlN2UxNmItNTMyMC00OTc0LTgxZDAtYmZkMTIyMzVh
N2E1MRYwFAYDVQQLEw1pbnRlcm1lZGlhaXJlMTUwMwYDVQQKEyxRTEE4ejdTYUx4
NFpGVHlSYlVkUGllam9qbTVoVWZxeGNQUmN3c3VpVlI4VDAeFw0yMTAyMTUyMDAz
NDNaFw0yMTAzMTcyMDA1NDNaMHgxNTAzBgNVBAoMLFFMQTh6N1NhTHg0WkZUeVJi
VWRQaWVqb2ptNWhVZnF4Y1BSY3dzdWlWUjhUMRAwDgYDVQQLDAdtb25pdG9yMS0w
KwYDVQQDDCRiMGU3ZTE2Yi01MzIwLTQ5NzQtODFkMC1iZmQxMjIzNWE3YTUwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDl/fpKc+Wu+LcatADxy3ViBX54
n3EK1LEWZJWC6AQR8hGGkaxxtgiyoasMJiblrqnZommcjk399D60Ix2GeMNoCEfu
TWpoxDz7VXFfTQFiUExDwPWqKAdQSeK0B9JUQMyh/0IKH9ARWqnUg9c6Q3DUpHCO
iIqEc3YN9yi+wFplTFnrzemBLYhsql+gNwq5YseqX/ZaV7iM+MoLkYdYERJPlGIA
aYiSD10BZ9K5XXzdXyz8UBwfzJC2haP5fCKjWalusz0d7FLAqVQtLSOf+EANJiQ5
xlbo8HZyqKc9zOChukQDiO4mGNIm0O8aghl9ypAybyX3gJxKJj0UEJTkwEHtAgMB
AAGjgecwgeQwHQYDVR0OBBYEFJfXeAZw7qYc+XASOU6CcUVbfsm6MB8GA1UdIwQY
MBaAFB87VTm4RcNiLLIQTLZ7KIEEu6chMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQD
AgTwMCIGBCoDBAAEGjQuc2VjdXJlLDMucHJvdGVnZSwyLnByaXZlMA8GBCoDBAEE
B21vbml0b3IwUgYDVR0RBEswSYIkYjBlN2UxNmItNTMyMC00OTc0LTgxZDAtYmZk
MTIyMzVhN2E1gglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDQYJ
KoZIhvcNAQELBQADggEBAAlPk0Efd4kpagvwRTyX5X5W//xnMZ1w47ITc0sGeT4e
uFJh5hBjzCoM56TCb1pQ7s7oM212HzEBvxS7HEcvejbihHFVxr7BFicEl640lFgC
7Za9w+CcJ8a9XoiXxj0n1eIEtP2+M3C+3989bo7Pu7XU3cTRg2MKQ4siMbF8eC5p
HGUcpspZKUewZYWd/jp2vQaUqe9PP/hLHLSQRySo8GVUIITyvbhDZMCaKcTSjbB3
SJhmTaxLKFP0ZMwHnanxpYUVCTgnhL/rjnVcphCyauevJfnz/F9jkQfqSiAnekXR
Mp0ZzHARNeA6hsAjgnIliyUkhw8/A6mH/PDyl+RSl/w=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDfzCCAmegAwIBAgIKBDNxl1cTgCQkADANBgkqhkiG9w0BAQ0FADAnMQ8wDQYD
VQQDEwZSYWNpbmUxFDASBgNVBAoTC01pbGxlR3JpbGxlMB4XDTIxMDIxNTIwMDUz
MVoXDTI0MDIxODIwMDUzMVowfjEtMCsGA1UEAxMkYjBlN2UxNmItNTMyMC00OTc0
LTgxZDAtYmZkMTIyMzVhN2E1MRYwFAYDVQQLEw1pbnRlcm1lZGlhaXJlMTUwMwYD
VQQKEyxRTEE4ejdTYUx4NFpGVHlSYlVkUGllam9qbTVoVWZxeGNQUmN3c3VpVlI4
VDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALIFnRbD8jatuetbT0xZ
G+FkzJWcTO/iiJmmy2An1rCxJYyII9UJwTT06iNmcBKN0j1RQQH9oys2S63EGWWn
BgKQDmqVXt+PKzcD/HT5OUfzkiviSC6eH7GNpDcSMPOBmeHpOqPhuLqhDQkopDiO
DzGBKr7o79M9+C6kCUptxKCs5EvJVOu0m3aCdVnlhFNnfVmwz1qE8df8HuFgIsK7
dnSPTXx98EkxfwibNjlhmfx2uaEQBNxG/EPkdtkZqKOgluMvVV29z0+ursNmtkR2
IWTkPdel8eLaFBmQxws35+RzBdv1IJAyuQLt8r84k5HODIY4gJEwtQSw/LmXWACg
Us0CAwEAAaNWMFQwEgYDVR0TAQH/BAgwBgEB/wIBBDAdBgNVHQ4EFgQUHztVObhF
w2IsshBMtnsogQS7pyEwHwYDVR0jBBgwFoAULmWyQdaWzDUSLJesMFG5FvsCF1cw
DQYJKoZIhvcNAQENBQADggEBADGcUWDBJdgXiY4xImmP10PR1iVI5IhmORU8BrSg
2xN8EST8aRQn3FaPRTxiCAhHyPGf+DAH5aFAcQZn7bB0hqKS1yuoYGK71EM2j63W
l7+aGZ1W6+1Gm2vUk4D2M3pqubWMgnJgNAynC6oJO3o8o3b+TwMkFRb8x2HCBF+v
SDMRXBfSxPxpgdibrTh/BW+d07aGjtQy1fggGAlRoHapqilaZ0f01r4r7fGaNEnD
bguzR11dLma1TokMYnK3uki2yUdWrW1sKhzh35PN9VmWSJJC0qmy30+WPHUm36/Z
U47D1s/j8pKzeq5C2pJiNcEwJP6WW16c0Ce/dWGlGh0KFjk=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDJzCCAg+gAwIBAgIJh4hTAQFkKTIAMA0GCSqGSIb3DQEBDQUAMCcxDzANBgNV
BAMTBlJhY2luZTEUMBIGA1UEChMLTWlsbGVHcmlsbGUwHhcNMjAxMDE1MTczNjQx
WhcNMjExMDE1MTczNjQxWjAnMQ8wDQYDVQQDEwZSYWNpbmUxFDASBgNVBAoTC01p
bGxlR3JpbGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoEQE8xzF
4BeTqnui0ri3F8wKGmF75xLKBUWklpc/FSnyIb6R/IfjoxT+tgI9Gr38lA9ITvdB
ykNAeS4HbKv4K7g+vIWJixGWXBspd0Fs7FKMwZgN/c1wpBZw4rPjujk8u385/Aiu
6WkCK0+QIPl5bmKWLIzs/wpcWt+g7vlFYSM7qKdvlxJ6LToqcZKrKVemPfokIJ+X
QNe6vWTSVKqTCETe9ltPxnftI2eELuHpSyigYwkEIjkQPRbShpm/GdO7MJJwfo0i
XJqAZabEAgJnCt1o0FNySRa8o5VThpiUDlbaAS77v0E/cgM8Q8+vbwZN3mAjzbn9
xBYdSC2KMT5MFQIDAQABo1YwVDASBgNVHRMBAf8ECDAGAQH/AgEFMB0GA1UdDgQW
BBQuZbJB1pbMNRIsl6wwUbkW+wIXVzAfBgNVHSMEGDAWgBQuZbJB1pbMNRIsl6ww
UbkW+wIXVzANBgkqhkiG9w0BAQ0FAAOCAQEAOML4p+SwPU+VeTikYrH4tPQsTXnC
Dt4VqI71MsTD4zOdKUN+voRaKQWO0RE3zcTfIcY784cDxvSrzpDWIkQ1OkAu9VvR
MX1f9dlX3J7jEywnpHnEZ6uphew0PIApumXVsumGsztw+X8RAL8tX9a4V/xSzHwM
Gls59U8FYZbvfIeo+IYxjbiK2tY44qU76tETdhJkUqbYwZKLveRv8UIjmaFAoybA
CbpFuvHsuGMpL1Eg+nqDyn7z4GjAsjxu5UrCTlzXkUXyvGUcZ87zWFJo7ftG4EyM
1D5hhfH0whmeLRxOs/BkYThHe3q+uis8K9R6qbdvXXmuw/nVUQU7QmL0mA==
-----END CERTIFICATE-----
`

const PEM_CLE = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDl/fpKc+Wu+Lca
tADxy3ViBX54n3EK1LEWZJWC6AQR8hGGkaxxtgiyoasMJiblrqnZommcjk399D60
Ix2GeMNoCEfuTWpoxDz7VXFfTQFiUExDwPWqKAdQSeK0B9JUQMyh/0IKH9ARWqnU
g9c6Q3DUpHCOiIqEc3YN9yi+wFplTFnrzemBLYhsql+gNwq5YseqX/ZaV7iM+MoL
kYdYERJPlGIAaYiSD10BZ9K5XXzdXyz8UBwfzJC2haP5fCKjWalusz0d7FLAqVQt
LSOf+EANJiQ5xlbo8HZyqKc9zOChukQDiO4mGNIm0O8aghl9ypAybyX3gJxKJj0U
EJTkwEHtAgMBAAECggEAEMc3dCkCT4JrcTJCg2ExXgZClLAlAgJELPsHgTZF3b1I
FAYai20ZM1bh8I/z9HuKfor/o2EqRWWFEYUiSUYUE0nPXY4ePihavoccLzSh7jcn
aSXxhglHh07sj++mI2laxFKn0a9CcZGopA0+LUzwNUMNxwgk+saljR1Dxq6nqY4F
8T1ZOZ7yobOA4yq+LvB5c/WK2jpPJ7qEpO5/jYKjv7KjU2u1UET402p90dSZXK/m
D5Xm0OWgWFXkmwfUOHbSfftcssrbnv36wXdu0g/wQpoWIaluHunkBAC9AvquVyT5
xZe32Mojhm16/qX/oLRKXGFuMF+S1/v6vkkoZxXIYQKBgQD6rma4rTXaf/x1kW8I
231ZZen8o9PF9IaouqkFHmoftr4rdpB7qSOMI/Y4gUOu9uJ/JVZWFxb7zWYYQX5U
c+oE0oHk41Cy8lEoLP4G1MPvY//AEidko9TgWC4DNTdIJ7XiCC1/v4ny4fVXiHpm
QDGnCTSnFHPpzn0QYiR7PBaMWQKBgQDq3zOMVqmLFdkzbrNfpD8LZk080UeHLn9I
Rd7KgsjhqJymjVOThh1kyjQ6Fo8cmLmuPf+yEom3ExcJBM4+ZogrSXkcyQ/nB3+l
8/cyIb8WUiyCeZGSWhjORzPaZamavCDtRrkBP4Y8CFnvsvX2Pd6R2KduB9kRY5Mu
m8KDIUpftQKBgCDiQd1V82uPQHnXsx4RVNcmVFRs1Tnxgrydh9CBFeDFIxsmeXuP
S3d1vDXbVxqbjkipiDLQ4pXzcsIZzU2cywUI7DsvSoW+3cCMbmJNBMrhbkou13YP
O7yWNKr9DxxrASP+eKF6ackvtPRfldbV8u17eqm0OCRijutYRHrZ/gc5AoGBAOYd
vVGYbxB4XZAIu/HO6H3ww2f824nUwpw66KedL9f37VM5UFNPqWjgu/7Vr22jLPlM
gUMk6ozWRVFuxetZZbyThffv/oaqUCR2PRF/AsuJw1YqabfsUjV4iZNG279g5xnS
mtxgMtKKlCNHQbj6sSBQFuq1AbYJy2B090Smz0mpAoGAF5CcgOxejoQUA4ngXcYa
F33Ff2lVJu871/2/W9Vda//I314SFtqWoGhx+YBPUTk9e9lkroQOITFcH+3yxEKH
skFyiMemLGpI4PW4oTQ+UG/aYe7QreLfQNxnHGOPMlJVO3F+2pqiygy8P6ppnWAr
9R3lMm+MGku4P7NELGtQAc4=
-----END PRIVATE KEY-----
`

describe('hacher message', ()=>{

  test('message 1', async ()=>{
    const hachage = await hacherMessage(MESSAGE_1)
    console.debug("Message : %O --> hachage : %s", MESSAGE_1, hachage)
    expect(hachage).toBe(HACHAGE_MESSAGE_1)
  })

  test('message 2', async ()=>{
    const hachage = await hacherMessage(MESSAGE_2)
    console.debug("Message : %O --> hachage : %s", MESSAGE_2, hachage)
    expect(hachage).toBe(HACHAGE_MESSAGE_2)
  })

})

var signateur = null
describe('signerMessage', ()=>{

  beforeEach(()=>{
    signateur = new SignateurMessage(PEM_CLE)
  })

  test('message 1', async ()=>{
    const signature = await signateur.signer(MESSAGE_1)
    console.debug("Signature : %O", signature)
    expect(signature).not.toBeNull()
  })

})

var formatteur = null
describe('formatter message', ()=>{

  beforeEach(()=>{
    formatteur = new FormatteurMessage(PEM_CERT, PEM_CLE)
  })

  test('formatter message 1', async ()=>{
    const resultat = await formatteur.formatterMessage(MESSAGE_1, 'Domaine.test')
    //console.debug("Resultat formatter message 1\n%O", resultat)
    expect(resultat['en-tete'].domaine).toBe('Domaine.test')
    expect(resultat['en-tete'].version).toBe(1)
    expect(resultat['en-tete'].idmg).toBe('QLA8z7SaLx4ZFTyRbUdPiejojm5hUfqxcPRcwsuiVR8T')

    expect(resultat['en-tete'].hachage_contenu).toBe('mEiC7ijJQr6Bbj8m/ggWWKzt0HrTfVK29c630658ep9OR1Q')
    expect(resultat['en-tete'].fingerprint_certificat).toBe('zQmYunN1ANPbuxtzHmNHz4QaXpeM3crm3iVbpSogHihkjvi')

    expect(resultat['en-tete'].estampille).not.toBeNull()
    expect(resultat['en-tete'].uuid_transaction).not.toBeNull()
    expect(resultat['_signature']).not.toBeNull()
  })

  test('formatter message 2', async ()=>{
    const resultat = await formatteur.formatterMessage(MESSAGE_2, 'Domaine.test')
    //console.debug("Resultat formatter message 1\n%O", resultat)
    expect(resultat['en-tete'].domaine).toBe('Domaine.test')
    expect(resultat['en-tete'].version).toBe(1)
    expect(resultat['en-tete'].idmg).toBe('QLA8z7SaLx4ZFTyRbUdPiejojm5hUfqxcPRcwsuiVR8T')

    expect(resultat['en-tete'].hachage_contenu).toBe('mEiCTYQUmipCIDGauFwcwtEJW7hJUhrrpqGHUcNZHj3S+oA')
    expect(resultat['en-tete'].fingerprint_certificat).toBe('zQmYunN1ANPbuxtzHmNHz4QaXpeM3crm3iVbpSogHihkjvi')

    expect(resultat['en-tete'].estampille).not.toBeNull()
    expect(resultat['en-tete'].uuid_transaction).not.toBeNull()
    expect(resultat['_signature']).not.toBeNull()
  })

})
