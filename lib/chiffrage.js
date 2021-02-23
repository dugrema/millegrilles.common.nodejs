const multibase = require('multibase')
const {random: forgeRandom, cipher: forgeCipher, util: forgeUtil} = require('node-forge')

const {hacher} = require('./hachage')

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
    resultatChiffrage = await _chiffrerSubtle(contenu, opts)
  } else {
    resultatChiffrage = _chiffrerForge(contenu, opts)
  }

  // Retourner tous les elements du chiffrage
  const resultat = {
    ciphertext: resultatChiffrage.ciphertext,
    password: resultatChiffrage.password,
    meta: {
      iv: multibase.encode('base64', resultatChiffrage.iv),
      tag: multibase.encode('base64', resultatChiffrage.tag),
      hachage_bytes: resultatChiffrage.hachage_bytes,
    }
  }

  return resultat
}

async function chiffrerForge(contenu, opts) {
  opts = opts || {}

  if(typeof(contenu) === 'string') {
    contenu = forgeUtil.createBuffer(forgeUtil.encodeUtf8(contenu), 'utf8')
  } else {
    // Convertir AB vers byte string
    contenu = forgeUtil.createBuffer(contenu, 'raw')
  }

  // Generer IV et password random
  var password = opts.password
  if( ! password ) {
    password = await forgeRandom.getBytes(32)
  }
  const iv = await forgeRandom.getBytes(12)

  const cipher = forgeCipher.createCipher('AES-GCM', password)
  cipher.start({iv})
  cipher.update(contenu)
  cipher.finish()

  var ciphertext = cipher.output
  const tag = cipher.mode.tag

  // Convertir en buffer
  ciphertext = Buffer.from(ciphertext.getBytes(), 'binary')

  const hachage_bytes = await hacher(ciphertext, {hashingCode: 'sha2-512', encoding: 'base64'})

  return {
    ciphertext,
    password: Buffer.from(password, 'binary'),
    meta: {
      iv: String.fromCharCode.apply(null, multibase.encode('base64', Buffer.from(iv, 'binary'))),
      tag: String.fromCharCode.apply(null, multibase.encode('base64', Buffer.from(tag.getBytes(), 'binary'))),
      hachage_bytes,
    }
  }

}


async function dechiffrerAESGCM(contenu, cleSecrete, iv, tag) {
  // Contenu doit etre : string multibase ou Buffer
  // Les autres parametres doivent tous etre format multibase
  opts = opts || {}

  if(typeof(contenu) === 'string') {
    // Encodage en multibase
    contenu = multibase.decode(contenu)
  }

  const cleBuffer = multibase.decode(cleSecrete)
  const ivBuffer = multibase.decode(iv)
  const tagBuffer = multibase.decode(tag)



}

async function dechiffrerForge(ciphertext, password, iv, tag) {
  ciphertext = forgeUtil.createBuffer(ciphertext, 'raw')

  console.debug("Params IV: %O, TAG: %O", iv, tag)
  const ivArray = multibase.decode(iv)
  const tagArray = multibase.decode(tag)
  console.debug("Array IV: %O, TAG: %O", ivArray, tagArray)

  const passwordBytes = String.fromCharCode.apply(null, password)
  const ivBytes = String.fromCharCode.apply(null, ivArray)
  const tagBytes = String.fromCharCode.apply(null, tagArray)

  console.debug("IV : %O, tag: %O", ivBytes, tagBytes)

  var decipher = forgeCipher.createDecipher('AES-GCM', passwordBytes)
  decipher.start({
    iv: ivBytes,
    tag: tagBytes,
  })
  decipher.update(ciphertext);
  var pass = decipher.finish()

  if(pass) {
    // outputs decrypted hex
    return Buffer.from(decipher.output.getBytes(), 'binary')
  } else {
    throw new Error("Erreur de dechiffrage - invalid tag")
  }

}


async function creerCipher() {

}

async function creerDecipher() {

}

module.exports = {
  chiffrerForge, dechiffrerForge,
}
