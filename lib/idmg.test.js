const {encoderIdmg, verifierIdmg} = require('./idmg')

const IDMG_V1 = 'QLA8z7SaLx4ZFTyRbUdPiejojm5hUfqxcPRcwsuiVR8T'
const IDMG_V2 = 'z2MFCe7c6DfeMwTYpSJBGRPhiyt3peu1ucycDGDReGJQTpidp4ABPi'
const CERT_PEM = `
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


describe('idmg', ()=>{

  test('creer idmg', async ()=>{
    const idmg = await encoderIdmg(CERT_PEM)
    console.debug("IDMG calcule : %s", idmg)
    expect(idmg).toBe(IDMG_V2)
  })

  test('verifier idmg v2', async ()=>{
    const idmg = await verifierIdmg(IDMG_V2, CERT_PEM)
    console.debug("IDMG calcule : %s", idmg)
  })

  test('verifier idmg v1', async ()=>{
    const idmg = await verifierIdmg(IDMG_V1, CERT_PEM)
    console.debug("IDMG calcule : %s", idmg)
  })

})
