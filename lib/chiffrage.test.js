const {util: forgeUtil, pki: forgePki} = require('node-forge')
const fs = require('fs')
const multibase = require('multibase')

const {
  chiffrerForge, dechiffrerForge, creerCipher, creerDecipher, chiffrerDocument,
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
    console.debug("Resultat : %O", resultat)

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
    console.debug("Password charge : %O", password)

    var resultat = await dechiffrerForge(ciphertext, password, iv, tag)
    console.debug("dechiffrer string forge resultat : %O", resultat)

    // Convertir resultat en texte
    resultat = String.fromCharCode.apply(null, resultat)

    console.debug("Resultat dechiffrage : %O", resultat)

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
    console.debug("Resultat dechiffrage cycle : %s", resultatDechiffrage)
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
      console.debug("DATA len %d", data.length)
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
    console.debug("Resultat cipher block %O\nBytes chiffres: %d", resultat, bytesChiffres)
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
    console.debug("Password: %s", password)
    console.debug("Resultat cipher block %O", resultat)

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

    const resultat = chiffrerCleSecreteForge(certForge.publicKey, cleSecrete, {DEBUG: true})
    console.debug("Resultat: %O", resultat)
    console.debug("Version multibase : %s", String.fromCharCode.apply(null, multibase.encode('base64', resultat)))
  })

  test.only('dechiffrer cle secrete 1', ()=>{
    const cle = keys.CLE_MAITRECLES
    const cleForge = forgePki.privateKeyFromPem(cle)

    const cleSecrete = dechiffrerCleSecreteForge(cleForge, TEST_SECRET_CHIFFRE_1, {DEBUG: true})
    const cleSecreteStr = String.fromCharCode.apply(null, cleSecrete)
    console.debug("Cle secrete dechiffree : %O = %s", cleSecrete, cleSecreteStr)
    expect(cleSecreteStr).toBe(PASSWORD_1_DECHIFFRE)
  })

  test('dechiffrer cle secrete 2', ()=>{
    const cle = keys.CLE_MAITRECLES
    const cleForge = forgePki.privateKeyFromPem(cle)

    const cleSecrete = dechiffrerCleSecreteForge(cleForge, TEST_SECRET_CHIFFRE_2, {DEBUG: true})
    const cleSecreteMb = String.fromCharCode.apply(null, multibase.encode('base64', cleSecrete))
    expect(cleSecreteMb).toBe(PASSWORD_2_DECHIFFRE)
  })

})
