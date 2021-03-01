const {util: forgeUtil, pki: forgePki} = require('node-forge')
const fs = require('fs')
const multibase = require('multibase')

const {
  chiffrerForge, dechiffrerForge, creerCipher, creerDecipher,
  chiffrerDocument, dechiffrerDocument,
  chiffrerCleSecreteForge, dechiffrerCleSecreteForge,
} = require('./chiffrage')
const {hacher} = require('./hachage')

const certs = require('../samples/certificat_pems')
const keys = require('../samples/cles_pems')

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
    const message = 'Tester 1 chiffrage'
    const resultat = await chiffrerForge(message)
    // console.debug("Resultat : %O", resultat)

    expect(resultat.meta.iv).not.toBeNull()
    expect(resultat.meta.tag).not.toBeNull()
    expect(resultat.meta.hachage_bytes).not.toBeNull()
    expect(resultat.password).not.toBeNull()
    expect(resultat.ciphertext).not.toBeNull()

    const hachage = await hacher(resultat.ciphertext, {encoding: 'base58btc', hash: 'sha2-512'})
    expect(hachage).toBe(resultat.meta.hachage_bytes)
  })

  test('dechiffrer string forge', async ()=> {
    var ciphertext = MESSAGE_1_CHIFFRE.ciphertext
    var password = MESSAGE_1_CHIFFRE.password
    const iv = MESSAGE_1_CHIFFRE['meta'].iv
    const tag = MESSAGE_1_CHIFFRE['meta'].tag

    ciphertext = Buffer.from(ciphertext, 'base64')
    password = Buffer.from(password, 'base64')
    // console.debug("Password charge : %O", password)

    var resultat = await dechiffrerForge(ciphertext, password, iv, tag)
    // console.debug("dechiffrer string forge resultat : %O", resultat)

    // Convertir resultat en texte
    resultat = String.fromCharCode.apply(null, resultat)

    // console.debug("Resultat dechiffrage : %O", resultat)

  })

  test('cycle chiffrage / dechiffrage forge', async ()=>{
    const message = 'Message tester cycle chiffrage/dechiffrage'
    const resultat = await chiffrerForge(message)

    const hachage = await hacher(resultat.ciphertext, {encoding: 'base58btc', hash: 'sha2-512'})
    expect(hachage).toBe(resultat.meta.hachage_bytes)

    var ciphertext = resultat.ciphertext
    var password = resultat.password
    const iv = resultat['meta'].iv
    const tag = resultat['meta'].tag

    ciphertext = Buffer.from(ciphertext, 'base64')
    password = Buffer.from(password, 'base64')

    var resultatDechiffrage = await dechiffrerForge(ciphertext, password, iv, tag)
    resultatDechiffrage = String.fromCharCode.apply(null, resultatDechiffrage)
    // console.debug("Resultat dechiffrage cycle : %s", resultatDechiffrage)
    expect(resultatDechiffrage).toBe(message)
  })

})

describe('chiffrage par block', ()=>{
  test('chiffrer image', async ()=>{
    // const readStream = fs.createReadStream('/home/mathieu/BinLadenSeaShell.jpg')
    const readStream = fs.createReadStream('/home/mathieu/skeletor_olives.jpg')
    const cipher = await creerCipher()
    var bytesChiffres = 0
    readStream.on('data', data=>{
      // console.debug("DATA len %d", data.length)
      bytesChiffres += data.length
      const ciphertextBlock = cipher.update(data)
    })
    const promise = new Promise((resolve, reject)=>{
      readStream.on('end', async ()=>{
        const resultat = await cipher.finish()
        resolve(resultat)
      })
      readStream.on('error', err=>reject(err))
    })

    readStream.read()
    const resultat = await promise
    // console.debug("Resultat cipher block %O\nBytes chiffres: %d", resultat, bytesChiffres)
  })

  test('cycle chiffrer / dechiffrer image', async ()=>{
    const sourcePath = '/home/mathieu/skeletor_olives.jpg'
    const chiffrePath = '/tmp/outputcipher.mgs2'

    const readStream = fs.createReadStream(sourcePath)
    const writeStream = fs.createWriteStream(chiffrePath)
    const cipher = await creerCipher()

    readStream.on('data', data=>{
      const ciphertextBlock = cipher.update(data)
      writeStream.write(ciphertextBlock)
    })

    const promise = new Promise((resolve, reject)=>{
      readStream.on('end', async ()=>{
        const resultat = await cipher.finish()
        resolve(resultat)
      })
      readStream.on('error', err=>{
        reject(err)
      })
    }).finally(()=>{
      writeStream.close()
    })

    readStream.read()
    const resultat = await promise
    const password = String.fromCharCode.apply(null, multibase.encode('base64', new Uint8Array(resultat.password)))
    // console.debug("Password: %s", password)
    // console.debug("Resultat cipher block %O", resultat)

    const iv = resultat['meta'].iv
    const tag = resultat['meta'].tag

    const decipher = creerDecipher(resultat.password, iv, tag)
    const readStreamDecipher = fs.createReadStream(chiffrePath)
    const writeStreamDecipher = fs.createWriteStream('/tmp/outputdecipher.jpg')

    readStreamDecipher.on('data', data=>{
      const deciphertextBlock = decipher.update(data)
      writeStreamDecipher.write(deciphertextBlock)
    })

    const promiseDecipher = new Promise((resolve, reject)=>{
      readStreamDecipher.on('end', async ()=>{
        const resultat = await decipher.finish()
        writeStreamDecipher.write(resultat)
        resolve()
      })
      readStreamDecipher.on('error', err=>{
        reject(err)
      })
    }).finally(()=>{
      writeStreamDecipher.close()
    })

    await promiseDecipher

  })
})

const TEST_SECRET_CHIFFRE_1 = 'mOpu5lKN6mkzJW7TlqLA9hr82YpWoAVqWOuZkcwWSK80rpTtrBpTAXHp4hSQVXSyplQ9QQ/3NOpoTB2ocSQN6Lj/WOWhbM0OReZ24DaU0gSx4FhP0rMio1WeIE3RLppYnN29xWL73p27MGHPp83ZAbISQSVwmFdwqbLGALBDw9n+noqPeMPEq/VcR8+gd48exnKSRrogJ6e3JqH2+snDVYjYzWCECqzZRMqhf/+4cHANpVAIyXWRgRx/hreyEaemIqfsf1tPOJRbbDBFV5FOd7FSYmu/geARzYl3S7ZdJuSn8XWk8iNFXEzL+wJHQIO0jR71WXGAPwAkB5YxCiZwd6g'
const PASSWORD_1_DECHIFFRE = 'maclesecrete1234'
const TEST_SECRET_CHIFFRE_2 = "mh4P1n8aD/byx5+iEt9NU1JEV7JUT7n19lowKrwerkm3cQwLu3e//cZBdcya+2wdEIuYyMW/xlzL2l16o/OZGOzZzA6ZsTWM/9EhuMW+0GO6pwM53vWcooTBcc4HkEX5/6ZkbGUMFn+b/ii34QsrWi7u8NW39UtgcKy5+cS3M0s118yYXDOguJ3UXn8jgpxNYgM3deoFb2KlCRt+rgODTckQweSaOL0xGhsO7g8z4flKvoLfKZN2D5QmDAJK2T1OlUcya+EAnNSN7hT05s7AAQOy2MLS2IGQG1QDp02qlLVbxZWX8bLI9OlDTZ12voK4LcCreqzWqqhNpWDzhiXXc0w"
const PASSWORD_2_DECHIFFRE = 'mOBMFwIz7F9bgQvcrQ9xtAxAKBHpozGNQZt6AfYIVdFM'

describe('chiffrage asymmetrique', ()=>{

  test('chiffrer cle secrete', ()=> {
    const cert = certs.CERT_MAITRECLES
    const certForge = forgePki.certificateFromPem(cert)

    const cleSecrete = Buffer.from(PASSWORD_1_DECHIFFRE, 'binary')

    const resultat = chiffrerCleSecreteForge(certForge.publicKey, cleSecrete, {DEBUG: false})
    // console.debug("Resultat: %O", resultat)
    // console.debug("Version multibase : %s", String.fromCharCode.apply(null, multibase.encode('base64', resultat)))
  })

  test('dechiffrer cle secrete 1', ()=>{
    const cle = keys.CLE_MAITRECLES
    const cleForge = forgePki.privateKeyFromPem(cle)

    const cleSecrete = dechiffrerCleSecreteForge(cleForge, TEST_SECRET_CHIFFRE_1, {DEBUG: false})
    const cleSecreteStr = String.fromCharCode.apply(null, cleSecrete)
    // console.debug("Cle secrete dechiffree : %O = %s", cleSecrete, cleSecreteStr)
    expect(cleSecreteStr).toBe(PASSWORD_1_DECHIFFRE)
  })

  test('dechiffrer cle secrete 2', ()=>{
    const cle = keys.CLE_MAITRECLES
    const cleForge = forgePki.privateKeyFromPem(cle)

    const cleSecrete = dechiffrerCleSecreteForge(cleForge, TEST_SECRET_CHIFFRE_2, {DEBUG: false})
    const cleSecreteMb = String.fromCharCode.apply(null, multibase.encode('base64', cleSecrete))
    expect(cleSecreteMb).toBe(PASSWORD_2_DECHIFFRE)
  })

})

const DOCUMENT_TEST_1 = {texte: 'Allo', valeur: 23}

const DOCUMENT_CHIFFRE_1 =  {
  ciphertext: 'mjtB6U2wxmXlDesGrXFkZj7s/1T7AgprXuh6eVA',
  documentCle: {
    domaine: 'test.domaine',
    identificateurs_document: { type: 'test' },
    hachage_bytes: 'z8Vvp9UcaPiW2ZsQFBds5UZEikJ1dSWv4z3vxvao9o4qAxzcZwoiNdrisAjSuz6Kd8xdiJmV3YSKLTAEdnrPeYjgTbr',
    format: 'mgs2',
    iv: 'mL9dVdFdQ4lHNaPdK',
    tag: 'mek+TEgsKjb0PVRcP3zIHGA',
    cle: 'muK23C09pMYa0ZDBNVbSMsoH2IedF5kt3BebU0eFM1FG+HWVsRn4RDY1kOUvAty9CMbF39v7JCcmjhxtYhFqZIevUc9M9Bs5mOlUtiiwwHAjWFAt5T285bprD6XPgCJPT0cu24KWxTteDnfBhqrgTz7gjkPbLAhO0CBTzv3FboqgP5Z9pSk9BB1UxvBVxgKjF8szNlx+WPIjsb65n46rtw4ACmQmtElJRQThKg6bDUOp4ZeDaxC+95lp6AlIEKcYcu80X2SbeHyzJjzfcdNNlkOkMpRNIBDVP5qTWsPmw2ttWcBcvDL9y1xk45+b7wmC4zc46TqknffjwAG5c50/kVQ'
  }
}

describe('chiffrage documents', () => {
  test('chiffrer document', async ()=>{
    const cert = certs.CERT_MAITRECLES

    const resultat = await chiffrerDocument(
      DOCUMENT_TEST_1, 'test.domaine',
      [certs.CERT_MAITRECLES, certs.CERT_MILLEGRILLE],
      {'type': 'test'},
      {DEBUG: false}
    )

    // console.debug("Resultat : %O", resultat)
    expect(resultat.ciphertext).not.toBeNull()
    expect(resultat.commandeMaitrecles).not.toBeNull()
  })

  test('dechiffrer document', async ()=>{
    const cle = keys.CLE_MAITRECLES
    const clePrivee = forgePki.privateKeyFromPem(cle)

    const ciphertext = Buffer.from(multibase.decode(DOCUMENT_CHIFFRE_1.ciphertext), 'binary')

    const resultat = await dechiffrerDocument(
      ciphertext, DOCUMENT_CHIFFRE_1.documentCle, clePrivee,
      {DEBUG: false}
    )
    // console.debug("Resultat dechiffrage : %O", resultat)
    expect(resultat).toEqual(DOCUMENT_TEST_1)
  })

})
