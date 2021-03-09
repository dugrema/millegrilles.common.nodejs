const {hacher, verifierHachage, Hacheur, VerificateurHachage, hacherPassword} = require('./hachage')

const valeur = 'allo',
      valeur2 = Buffer.from('Q2VjaSBlc3QgdW4gY29udGVudSBxdWUgamUgdmFpcyBlbmNvZGVyIGVuIGJhc2U2NCBwb3VyIGRhdXRyZXMgcmFpc29ucw==', 'base64'),
      valeur3 = 'ÀÉËÊÈÇÏÎÔÛŨÙàéëèçïîôù¤{}[]¬~`°|/\'"\n\\'

const RESULTAT1_SHA512 = "z8Vv8e3sDPugPF1NNhssx3qBCKr8PHEBHfUmeSHb9GJz4NP3mHhthPgZYpNJnj8C5PDraUeBDDDoPbEyQgAYhfVoLYY"
const RESULTAT1_SHA256 = "zQmZJH8hPKTmyjwPTdBFd5Zf7nMBfyAba5sxUzdSS9Z1URp"
const RESULTAT2_SHA512 = "z8VwpBgJsmAmRpoE1Vy7sBDKa4oLNXePdsXiLEVM9csn2aQhdYfCg9Cnk86KEiXp1YYKSTWXeHmcDDWVqvcTWX16WZA"
const RESULTAT2_SHA256 = "zQmSr4HprgGSKvX9ADQWyFndzWVLMCK83XYD9mJqNkUcspi"
const RESULTAT3_SHA512 = "z8VujidaiuXmk2EFUmojr3Jw75CFHmvn4q6sCWRgBxhk5wq1NTc8t9wPAHmgok2yqjtBieDNpWjQeFPeZaJY4b2fYHB"
const RESULTAT_1_2_SHA512 = "z8VuWGoQqMpe2cLDxDMKgzk3PSfcdw97dJn2LdqibGuwHh7gU7batMrETmCEHnavZfd5D16zLoZxDWtmHuZcKodFpjC"
const RESULTAT_1_2_SHA256 = "zQmfXyXwyRstLnzhQaQNe5wNe9xpvJLTaAtVxzge8MguxDT"

describe('hacher', ()=>{

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

  test('Hacher 3 chars speciaux sha512', async ()=>{
    const resultat3_512 = await hacher(valeur3)
    console.debug("resultat3_512: %O", resultat3_512)
    expect(resultat3_512).toBe(RESULTAT3_SHA512)
  })

})

describe('verifier hachage', ()=>{

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

  test('Verifier Hacher 3 sha512', async ()=>{
    const resultat = await verifierHachage(RESULTAT3_SHA512, valeur3)
    expect(resultat).toBe(true)
  })

})

describe('Hacheur', ()=>{

  test('Verifier Hacher 1 sha512', ()=>{
    const hacheur = new Hacheur()
    hacheur.update(valeur)
    const mh = hacheur.finalize()
    expect(mh).toBe(RESULTAT1_SHA512)
  })

  test('Verifier Hacher 1 sha256', ()=>{
    const hacheur = new Hacheur({hash: 'sha2-256'})
    hacheur.update(valeur)
    const mh = hacheur.finalize()
    expect(mh).toBe(RESULTAT1_SHA256)
  })

  test('Verifier Hacher 2 sha512', ()=>{
    const hacheur = new Hacheur()
    hacheur.update(valeur2)
    const mh = hacheur.finalize()
    expect(mh).toBe(RESULTAT2_SHA512)
  })

  test('Verifier Hacher 2 sha256', ()=>{
    const hacheur = new Hacheur({hash: 'sha2-256'})
    hacheur.update(valeur2)
    const mh = hacheur.finalize()
    expect(mh).toBe(RESULTAT2_SHA256)
  })

  test('Verifier Hacher 3 sha512', ()=>{
    const hacheur = new Hacheur()
    hacheur.update(valeur3)
    const mh = hacheur.finalize()
    expect(mh).toBe(RESULTAT3_SHA512)
  })

  test('Verifier Hacher 1-2 sha512', ()=>{
    const hacheur = new Hacheur()
    hacheur.update(valeur)
    hacheur.update(valeur2)
    const mh = hacheur.finalize()
    expect(mh).toBe(RESULTAT_1_2_SHA512)
  })

  test('Verifier Hacher 1-2 sha256', ()=>{
    const hacheur = new Hacheur({hash: 'sha2-256'})
    hacheur.update(valeur)
    hacheur.update(valeur2)
    const mh = hacheur.finalize()
    expect(mh).toBe(RESULTAT_1_2_SHA256)
  })

})

describe('VerificateurHachage', ()=>{

  test('Verifier Hacher 1 sha512', ()=>{
    const verif = new VerificateurHachage(RESULTAT1_SHA512)
    verif.update(valeur)
    verif.verify()
  })

  test('Verifier Hacher 1 sha256', ()=>{
    const verif = new VerificateurHachage(RESULTAT1_SHA256)
    verif.update(valeur)
    verif.verify()
  })

  test('Verifier Hacher 2 sha512', ()=>{
    const verif = new VerificateurHachage(RESULTAT2_SHA512)
    verif.update(valeur2)
    verif.verify()
  })

  test('Verifier Hacher 2 sha256', ()=>{
    const verif = new VerificateurHachage(RESULTAT2_SHA256)
    verif.update(valeur2)
    verif.verify()
  })

  test('Verifier Hacher 3 sha512', ()=>{
    const verif = new VerificateurHachage(RESULTAT3_SHA512)
    verif.update(valeur3)
    verif.verify()
  })

  test('Verifier Hacher 1-2 sha512', ()=>{
    const verif = new VerificateurHachage(RESULTAT_1_2_SHA512)
    verif.update(valeur)
    verif.update(valeur2)
    verif.verify()
  })

  test('Verifier Hacher 1-2 sha256', ()=>{
    const verif = new VerificateurHachage(RESULTAT_1_2_SHA256)
    verif.update(valeur)
    verif.update(valeur2)
    verif.verify()
  })

})

describe.only('pbkdf2', ()=>{

  test('password test', async ()=>{
    const key = await hacherPassword('test', 121259, 'mFiPRhe+eNT4qivXCgJ6cUg')
    expect(key).toBe('mqqAM3JmBwzfo+kQDFNJJ7PhO2VdZA4PUI+gdWtO+X0k')
  })

  test('password chars utf8', async ()=>{
    const password = 'ABCD浅き夢見じ酔ひもせず有為の奥山今日越えて我が世誰ぞ常ならむ色は匂へど散りぬるを!@#$%^*()_éàûüùÇËÈÉ'
    const key = await hacherPassword(password, 84447, 'mDcz2/foFgqC54IGHLzPLig')
    expect(key).toBe('m4uZvPuyRuAMcrCIXhTAOp3HTA/XUymcHDDb695oQYCQ')
  })


})
