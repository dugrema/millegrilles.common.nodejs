const {util: forgeUtil} = require('node-forge')

const {chiffrerForge, dechiffrerForge} = require('./chiffrage')

MESSAGE_1_CHIFFRE = {
    'ciphertext': 'fDWm5jZoBbF/+4awTYNCFuYZ',
    'password': 'in38+aou4BwZ0v5CEtSkCJZnwoN3WjI11IfQNfVDWxs=',
    'meta': {
        'iv': 'm/hohj48Ala84SFrB',
        'hachage_bytes': 'mE0D3QN71zbjnSV51xYY/JrYQEV+DYbGSxaxfb+oDolFgWJ987iNXqKvY3jPNIbv1ycm8jmnke5Ps1wMXBKi0dc/j',
        'tag': 'mV0zERwOcu7dwFSE6YfSNVA'
    }
}

describe('test chiffrage', ()=>{
  test('chiffrer string forge', async ()=>{
    const resultat = await chiffrerForge('Tester 1 chiffrage')
    console.debug("Resultat : %O", resultat)

    expect(resultat.meta.iv).not.toBeNull()
    expect(resultat.meta.tag).not.toBeNull()
    expect(resultat.meta.hachage_bytes).not.toBeNull()
    expect(resultat.password).not.toBeNull()
    expect(resultat.ciphertext).not.toBeNull()
  })

  test('dechiffrer string forge', async ()=> {
    var ciphertext = MESSAGE_1_CHIFFRE.ciphertext
    var password = MESSAGE_1_CHIFFRE.password
    const iv = MESSAGE_1_CHIFFRE['meta'].iv
    const tag = MESSAGE_1_CHIFFRE['meta'].tag

    ciphertext = Buffer.from(ciphertext, 'base64')
    password = Buffer.from(password, 'base64')
    console.debug("Password charge : %O", password)

    var resultat = await dechiffrerForge(ciphertext, password, iv, tag)

    // Convertir resultat en texte
    resultat = String.fromCharCode.apply(null, resultat)
    
    console.debug("Resultat dechiffrage : %O", resultat)

  })
})
