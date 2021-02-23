const {util: forgeUtil} = require('node-forge')
const fs = require('fs')
const multibase = require('multibase')

const {chiffrerForge, dechiffrerForge, creerCipher, creerDecipher} = require('./chiffrage')
const {hacher} = require('./hachage')

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

    const hachage = await hacher(resultat.ciphertext, {encoding: 'base64', hash: 'sha2-512'})
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

    const hachage = await hacher(resultat.ciphertext, {encoding: 'base64', hash: 'sha2-512'})
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

    var readStream = fs.createReadStream(sourcePath)
    var writeStream = fs.createWriteStream(chiffrePath)
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
    var readStream = fs.createReadStream(chiffrePath)
    var writeStream = fs.createWriteStream('/tmp/outputdecipher.jpg')

    readStream.on('data', data=>{
      const deciphertextBlock = decipher.update(data)
      //writeStream.write(deciphertextBlock)
    })

    const promiseDecipher = new Promise((resolve, reject)=>{
      readStream.on('end', async ()=>{
        const resultat = await decipher.finish()
        writeStream.write(resultat)
        resolve()
      })
      readStream.on('error', err=>{
        reject(err)
      })
    }).finally(()=>{
      writeStream.close()
    })

    await promiseDecipher

  })
})
