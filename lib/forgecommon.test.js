const {pki: forgePki} = require('node-forge')

const { validerChaineCertificats, hacherPem } = require('./forgecommon')
const { hacher } = require('./hachage')

const certs = require('../samples/certificat_pems')

const CLE_PUBLIQUE = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoEQE8xzF4BeTqnui0ri3
F8wKGmF75xLKBUWklpc/FSnyIb6R/IfjoxT+tgI9Gr38lA9ITvdBykNAeS4HbKv4
K7g+vIWJixGWXBspd0Fs7FKMwZgN/c1wpBZw4rPjujk8u385/Aiu6WkCK0+QIPl5
bmKWLIzs/wpcWt+g7vlFYSM7qKdvlxJ6LToqcZKrKVemPfokIJ+XQNe6vWTSVKqT
CETe9ltPxnftI2eELuHpSyigYwkEIjkQPRbShpm/GdO7MJJwfo0iXJqAZabEAgJn
Ct1o0FNySRa8o5VThpiUDlbaAS77v0E/cgM8Q8+vbwZN3mAjzbn9xBYdSC2KMT5M
FQIDAQAB
-----END PUBLIC KEY-----
`

describe('hachage', ()=>{

  test('hachage contenu base64', async ()=>{
    const contenu = 'gYBUpFO+78449A8uR/gfr0ePW2eNRrC0zr+VmfQg3RVXoBvUmbIny0M3ohetnCl1svGTikD165C72f/IF+v6m7UoBFnHq61XnV+s2DLngt4='
    const resultat = await hacher(contenu)
    console.debug("Resultat hachage : %O", resultat)

    expect(resultat).toBe('z8VvDvSDPGw56Rzf143ETiYuR2kn8AmVTdLCQNEGjRTBY7tw5nBmZFnjh4wtuA3pPX52VdeEz7CM7VaXFZ9guAKc9eF')
  });

  test('hachage cle publique', async ()=>{
    // const clePubliqueForge = forgePki.publicKeyFromPem(CLE_PUBLIQUE)
    // const hachageCle = hacherClePublique(clePubliqueForge)
    const hachageCle = await hacherPem(CLE_PUBLIQUE)
    // console.debug("Hachage cle : %O", hachageCle)
    expect(hachageCle).toBe('mEiDL5VRO3slQTAkNOzqJdNoSEgk454+P460IvI8CPH267Q')
  })

})

describe('validation certificats', ()=>{

  test('valider chaine', async ()=>{
    const samplePem = certs.CERT_MAITRECLES
    const resultat = await validerChaineCertificats(samplePem)
    console.debug("Resultat validation : %O", resultat)
  })

})
