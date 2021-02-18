const {hacher, verifierHachage} = require('./hachage')

const valeur = 'allo',
      valeur2 = Buffer.from('Q2VjaSBlc3QgdW4gY29udGVudSBxdWUgamUgdmFpcyBlbmNvZGVyIGVuIGJhc2U2NCBwb3VyIGRhdXRyZXMgcmFpc29ucw==', 'base64')

const RESULTAT1_SHA512 = "z8Vv8e3sDPugPF1NNhssx3qBCKr8PHEBHfUmeSHb9GJz4NP3mHhthPgZYpNJnj8C5PDraUeBDDDoPbEyQgAYhfVoLYY"
const RESULTAT1_SHA256 = "zQmZJH8hPKTmyjwPTdBFd5Zf7nMBfyAba5sxUzdSS9Z1URp"
const RESULTAT2_SHA512 = "z8VwpBgJsmAmRpoE1Vy7sBDKa4oLNXePdsXiLEVM9csn2aQhdYfCg9Cnk86KEiXp1YYKSTWXeHmcDDWVqvcTWX16WZA"
const RESULTAT2_SHA256 = "zQmSr4HprgGSKvX9ADQWyFndzWVLMCK83XYD9mJqNkUcspi"
const RESULTAT_1_2_SHA512 = "z8VuWGoQqMpe2cLDxDMKgzk3PSfcdw97dJn2LdqibGuwHh7gU7batMrETmCEHnavZfd5D16zLoZxDWtmHuZcKodFpjC"
const RESULTAT_1_2_SHA256 = "zQmfXyXwyRstLnzhQaQNe5wNe9xpvJLTaAtVxzge8MguxDT"

describe('hachage fichier', ()=>{

  test('Hacher 1 sha512', async ()=>{
    const resultat1_512 = await hacher(valeur)
    console.debug("resultat1_512: %O", resultat1_512)
    expect(resultat1_512).toBe(RESULTAT1_SHA512)
  })

  test('Hacher 1 sha256', async ()=>{
    const resultat1_256 = await hacher(valeur, {hashingCode: 'sha2-256'})
    console.debug("resultat1_512: %O", resultat1_256)
    expect(resultat1_256).toBe(RESULTAT1_SHA256)
  })

  test('Hacher 2 sha512', async ()=>{
    const resultat2_512 = await hacher(valeur2)
    console.debug("resultat1_512: %O", resultat2_512)
    expect(resultat2_512).toBe(RESULTAT2_SHA512)
  })

  test('Hacher 2 sha256', async ()=>{
    const resultat2_256 = await hacher(valeur2, {hashingCode: 'sha2-256'})
    console.debug("resultat2_256: %O", resultat2_256)
    expect(resultat2_256).toBe(RESULTAT2_SHA256)
  })

})

describe('verifier hachage fichier', ()=>{

  test('Verifier Hacher 1 sha512', async ()=>{
    const resultat = await verifierHachage(RESULTAT1_SHA512, valeur)
    expect(resultat).toBe(true)
  })

  test('Verifier Hacher 1 sha256', async ()=>{
    const resultat = await verifierHachage(RESULTAT1_SHA256, valeur)
    expect(resultat).toBe(true)
  })

  test('Verifier Hacher 2 sha512', async ()=>{
    const resultat = await verifierHachage(RESULTAT2_SHA512, valeur2)
    expect(resultat).toBe(true)
  })

  test('Verifier Hacher 2 sha256', async ()=>{
    const resultat = await verifierHachage(RESULTAT2_SHA256, valeur2)
    expect(resultat).toBe(true)
  })

})
