const multibase = require('multibase')
const {random: forgeRandom, cipher: forgeCipher, util: forgeUtil} = require('node-forge')

const {hacher, Hacheur} = require('./hachage')

// Charger subtle si disponible dans le navigateur
function detecterSubtle() {
  if( typeof(window) !== 'undefined' && window.crypto) return window.crypto.subtle
  return null
}
const _subtle = detecterSubtle()

async function chiffrer(contenu, opts) {
  /* Chiffrer une string utf-8 ou un Buffer */
  opts = opts || {}

  var resultatChiffrage
  if(_subtle) {
    return chiffrerSubtle(contenu, opts)
  } else {
    return chiffrerForge(contenu, opts)
  }
}

async function chiffrerSubtle(contenu, opts) {
  opts = opts || {}

  // Generer IV, password au besoin
  var tailleRandom = 12
  // if( !opts.password ) { tailleRandom += 32 }
  const randomBytes = new Uint8Array(tailleRandom);
  window.crypto.getRandomValues(randomBytes)
  const iv = randomBytes.slice(0, 12)
  // const password = opts.password || randomBytes.slice(12)
  // console.debug("Password : %O, IV: %O", password, iv)

  if(typeof(contenu) === 'string') {
    // Encoder utf-8 en bytes
    contenu = new TextEncoder().encode(contenu)
  }

  const cleSecreteSubtle = await _subtle.generateKey({name: 'AES-GCM', length: 256}, true, ['encrypt'])
  const password = await _subtle.exportKey('raw', cleSecreteSubtle)

  // console.debug("Cle secrete subtle : %O\npassword: %O", cleSecreteSubtle, password)

  var resultatBuffer = await _subtle.encrypt({...cleSecreteSubtle.algorithm, iv}, cleSecreteSubtle, contenu)
  // console.debug("Resultat chiffrage : %O", resultatBuffer)

  const resultatView = new Uint8Array(resultatBuffer)
  const longueurBuffer = resultatView.length
  const computeTag = resultatView.slice(longueurBuffer-16)
  resultatBuffer = resultatView.slice(0, longueurBuffer-16)

  // console.debug("Compute tag : %O\nCiphertext : %O", computeTag, resultatBuffer)

  const hachage_bytes = await hacher(resultatBuffer, {hashingCode: 'sha2-512', encoding: 'base64'})

  return {
    ciphertext: resultatBuffer,
    password,
    meta: {
      iv: String.fromCharCode.apply(null, multibase.encode('base64', iv)),
      tag: String.fromCharCode.apply(null, multibase.encode('base64', computeTag)),
      hachage_bytes,
    },
  }
}

async function chiffrerForge(contenu, opts) {
  opts = opts || {}

  const cipher = await creerCipher(opts)
  const ciphertext = cipher.update(contenu)
  const resultatChiffrage = await cipher.finish()
  resultatChiffrage.ciphertext = ciphertext

  return resultatChiffrage
}

function dechiffrer(ciphertext, password, iv, tag) {
  // Contenu doit etre : string multibase ou Buffer
  // Les autres parametres doivent tous etre format multibase
  if(_subtle) {
    return dechiffrerSubtle(ciphertext, password, iv, tag)
  } else {
    return dechiffrerForge(ciphertext, password, iv, tag)
  }

}

function dechiffrerForge(ciphertext, password, iv, tag) {
  const decipher = creerDecipher(password, iv, tag)
  var output = decipher.update(ciphertext)
  const outputFinishBlock = decipher.finish()
  return Buffer.concat([output, outputFinishBlock])
}

async function dechiffrerSubtle(ciphertext, password, iv, tag) {
  const ivArray = multibase.decode(iv)
  const tagArray = multibase.decode(tag)

  // Concatener le tag au ciphertext - c'est le format requis par subtle
  const concatBuffer = new Uint8Array(tagArray.length + ciphertext.byteLength)
  concatBuffer.set(new Uint8Array(ciphertext), 0)
  concatBuffer.set(new Uint8Array(tagArray), ciphertext.byteLength)

  const secretKey = await _subtle.importKey(
    'raw',
    password,
    {name: 'AES-GCM', length: 256, iv: ivArray},
    false,
    ['decrypt']
  )

  // Dechiffrer - note : lance une erreur si le contenu est invalide
  const resultat = await _subtle.decrypt(
    {name: 'AES-GCM', length: 256, iv: ivArray},
    secretKey,
    concatBuffer
  )

  return resultat
}

async function creerCipher(opts) {
  opts = opts || {}

  // Generer IV et password random
  var password = opts.password
  if( ! password ) {
    password = await forgeRandom.getBytes(32)
  }
  const iv = await forgeRandom.getBytes(12)

  const cipher = forgeCipher.createCipher('AES-GCM', password)
  const hacheur = new Hacheur({hash: 'sha2-512', encoding: 'base64'})
  cipher.start({iv})

  // Creer objet wrapper pour le cipher
  const cipherWrapper = {
    update: data => {

      if(typeof(data) === 'string') {
        data = forgeUtil.createBuffer(forgeUtil.encodeUtf8(data), 'utf8')
      } else {
        // Convertir AB vers byte string
        data = forgeUtil.createBuffer(data, 'raw')
      }

      cipher.update(data)

      const ciphertext = Buffer.from(cipher.output.getBytes(), 'binary')
      // console.debug("Ciphertext : %O", ciphertext)
      hacheur.update(ciphertext)

      return ciphertext
    },
    finish: ()=>_fermerCipher(cipher, password, iv, hacheur)
  }

  return cipherWrapper
}

async function _fermerCipher(cipher, password, iv, hacheur) {
  cipher.finish()

  var ciphertext = cipher.output
  const tag = cipher.mode.tag

  // Convertir en buffer
  ciphertext = Buffer.from(ciphertext.getBytes(), 'binary')
  hacheur.update(ciphertext)

  // const hachage_bytes = await hacher(ciphertext, {hashingCode: 'sha2-512', encoding: 'base64'})
  const hachage_bytes = hacheur.finalize()

  return {
    ciphertextFinalBlock: ciphertext,
    password: Buffer.from(password, 'binary'),
    meta: {
      iv: String.fromCharCode.apply(null, multibase.encode('base64', Buffer.from(iv, 'binary'))),
      tag: String.fromCharCode.apply(null, multibase.encode('base64', Buffer.from(tag.getBytes(), 'binary'))),
      hachage_bytes,
    }
  }
}

function creerDecipher(password, iv, tag) {

  // console.debug("Params IV: %O, TAG: %O", iv, tag)
  const ivArray = multibase.decode(iv)
  const tagArray = multibase.decode(tag)
  // console.debug("Array IV: %O, TAG: %O", ivArray, tagArray)

  const passwordBytes = String.fromCharCode.apply(null, password)
  const ivBytes = String.fromCharCode.apply(null, ivArray)
  const tagBytes = String.fromCharCode.apply(null, tagArray)

  // console.debug("IV : %O, tag: %O", ivBytes, tagBytes)

  var decipher = forgeCipher.createDecipher('AES-GCM', passwordBytes)
  decipher.start({
    iv: ivBytes,
    tag: tagBytes,
  })

  const decipherWrapper = {
    update: ciphertext => {
      ciphertext = forgeUtil.createBuffer(ciphertext, 'raw')
      decipher.update(ciphertext)
      return Buffer.from(decipher.output.getBytes(), 'binary')
    },
    finish: () => {
      var pass = decipher.finish()
      if(pass) {
        return Buffer.from(decipher.output.getBytes(), 'binary')
      } else {
        throw new Error("Erreur de dechiffrage - invalid tag")
      }
    }
  }

  return decipherWrapper
}

module.exports = {
  chiffrer, dechiffrer,
  chiffrerForge, dechiffrerForge, chiffrerSubtle, dechiffrerSubtle,
  creerCipher, creerDecipher,
}
