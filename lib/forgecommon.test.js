const {pki: forgePki} = require('node-forge')

const { validerChaineCertificats, hacherPem } = require('./forgecommon')
const { hacher } = require('./hachage')

const certs = require('../samples/certificat_pems')

const CLE_PUBLIQUE = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzrDUQODmZVGOgqnV5EoK
8IdMP9yVxpzTJMxufAUPncaNrgdJjiisclYv47J4IYXGayk3HeDD+w4MAGFf4sUB
QRKYSL062FVUAQtkGWmDCW5Krs5YRILrTBGbY+wsTEcU8gWozu1lniKFaHX1idxK
R7GiL4PPyRChP2bxbXxXpeNEPRHQeqMHy12ejeVdpytA+5+4oM3BO0sXn5UaPgXU
RKbojP3rFrtsDZfVkjDWoK6jmsY4VJoNTIrv1QYx8+NU4qc6Gjy9vqk29SX5yRfh
BYQ2jQPhJfyqn1a/Ks5UvFajQPxQ38iWvTh3JuajDoZuyw+qHfaj4PDjkfZR9odZ
WwIDAQAB
-----END PUBLIC KEY-----
`

const CLE_PUBLIQUE_2 = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw8XGggPNs6E4zWATtB75
Fmx7AX71LXJ2icYkq+ZVkjGIl816gOF6125Ggx+JsWj+5PEqbf0xA/TrzL82zGNY
SMpniSjpbWQxhkkWq5L+kCeUiE+qQBNgpMJ82ez49IDXEk3CpE640yiBYvpDutMp
UwFaHGZIlQrgoRFzi+7mf1mG8b6eXv3ppR3YL20W/crUTcS90MnBjpFX+M4916vy
+pH3wRI/g5OkSSKEoEEshLKCrFlHJjZE1j8n+7Mv7MhiojagzPD3bKcVbTBsaWQl
sLih1DqFW+pCun/9fp/dY9GKOpibdrQ9fCWLjRCH8Zx2H4PEJZmx3GCploEhtH5u
9QIDAQAB
-----END PUBLIC KEY-----
`


describe('hachage', ()=>{

  test('hachage contenu base64', async ()=>{
    const contenu = 'gYBUpFO+78449A8uR/gfr0ePW2eNRrC0zr+VmfQg3RVXoBvUmbIny0M3ohetnCl1svGTikD165C72f/IF+v6m7UoBFnHq61XnV+s2DLngt4='
    const resultat = await hacher(contenu)
    console.debug("Resultat hachage : %O", resultat)

    expect(resultat).toBe('z8VvDvSDPGw56Rzf143ETiYuR2kn8AmVTdLCQNEGjRTBY7tw5nBmZFnjh4wtuA3pPX52VdeEz7CM7VaXFZ9guAKc9eF')
  });

  test.only('hachage cle publique', async ()=>{
    // const clePubliqueForge = forgePki.publicKeyFromPem(CLE_PUBLIQUE)
    // const hachageCle = hacherClePublique(clePubliqueForge)
    const hachageCle = await hacherPem(CLE_PUBLIQUE)
    // console.debug("Hachage cle : %O", hachageCle)
    expect(hachageCle).toBe('mEiD2f+fyk6D7NtWr/ff+vfb6A84sRAH+9OmqcWkCAIMnYg')

    const hachageCle2 = await hacherPem(CLE_PUBLIQUE_2)
    expect(hachageCle2).toBe('mEiDXjkYcUFSxkgdZDoPKX9VFTKZFfCGHthHrEO9HcYo8+Q')
  })

})

describe('validation certificats', ()=>{

  test('valider chaine', async ()=>{
    const samplePem = certs.CERT_MAITRECLES
    const resultat = await validerChaineCertificats(samplePem)
    console.debug("Resultat validation : %O", resultat)
  })

})
