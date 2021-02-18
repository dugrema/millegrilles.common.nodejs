// Module de hachage, utilise subtle dans le navigateur lorsque c'est approprie
// Fallback sur node-forge
const multihash = require('multihashes')
const multibase = require('multibase')
const forge = require('node-forge')

// Charger subtle si disponible dans le navigateur
function detecterSubtle() {
  if(window && window.crypto) return window.crypto.subtle
  return null
}
const _subtle = detecterSubtle()

async function hacher(valeur, opts) {
  if(!opts) opts = {}
  const hashingCode = opts.hashingCode || 'sha2-512'
  const encoding = opts.encoding || 'base58btc'

  // Convertir la valeur en ArrayBuffer
  console.debug(`Type de la valeur : ${typeof(valeur)}`)

  // Hacher la valeur
  let digest
  if(_subtle && opts.forge !== true) {
    // Utiliser subtle dans le navigateur (native)
    digest = await _calculerHachageSubtle(valeur, {hash: hashingCode})
  } else {
    // Fallback sur node-forge
    digest = _calculerHachageForge(valeur, {hash: hashingCode})
  }
  const digestView = new Uint8Array(digest)

  // Creer le multihash
  const mhValeur = multihash.encode(digestView, hashingCode)
  console.debug("Multihash Valeur : %O", mhValeur)

  // Encoder en base58btc avec multibase
  var mbValeur = multibase.encode(encoding, mhValeur)
  mbValeur = new TextDecoder().decode(mbValeur)

  return mbValeur
}

function _calculerHachageSubtle(valeur, opts) {
  var hachageSubtle = opts.hash || 'sha2-512'

  if(typeof(valeur) === 'string') {
    valeur = new TextEncoder().encode(valeur)
  }

  if(hachageSubtle.indexOf('sha2-') > -1) {
    hachageSubtle = hachageSubtle.replace('sha2-', 'sha-')
  } else if(hachageSubtle.indexOf('sha') > -1 && hachage.indexOf('-') == -1) {
    hachageSubtle = hachageSubtle.replace('sha', 'sha-')
  }

  console.debug("Hachage subtle avec algo : %O", hachageSubtle)
  return _subtle.digest(hachageSubtle, valeur)  // Promise
}

function _calculerHachageForge(valeur, opts) {
  var hachage = opts.hash || 'sha2-512'

  let fonctionHachage
  if(hachage === 'sha2-512') {
    fonctionHachage = forge.md.sha512
  } else if(hachage === 'sha2-256') {
    fonctionHachage = forge.md.sha256
  } else {
    throw new Error(`Fonction hachage non supportee : ${hachage}`)
  }

  var resultatHachage = fonctionHachage.create()
    .update(valeur)
    .digest()
    .getBytes()

  resultatHachage = Buffer.from(resultatHachage, 'binary')

  return resultatHachage
}

async function verifierHachage(hachageMultibase, valeur, opts) {
  opts = opts || {}

  const mbBytes = multibase.decode(hachageMultibase)
  const mh = multihash.decode(mbBytes)

  const algo = mh.name
  const digest = mh.digest

  // Hacher la valeur
  let digestCalcule
  if(_subtle && opts.forge !== true) {
    // Utiliser subtle dans le navigateur (native)
    digestCalcule = await _calculerHachageSubtle(valeur, {hash: algo})
  } else {
    // Fallback sur node-forge
    digestCalcule = _calculerHachageForge(valeur, {hash: algo})
  }

  digestCalcule = new Uint8Array(digestCalcule)

  if( _comparerArraybuffers(digest, digestCalcule) ) {
    return true
  } else {
    throw new Error("Erreur hachage, mismatch")
  }
}

function _comparerArraybuffers(buf1, buf2) {
  // https://stackoverflow.com/questions/21553528/how-to-test-for-equality-in-arraybuffer-dataview-and-typedarray
  if (buf1.byteLength != buf2.byteLength) return false;
    var dv1 = new Uint8Array(buf1);
    var dv2 = new Uint8Array(buf2);
    for (var i = 0 ; i != buf1.byteLength ; i++)
    {
        if (dv1[i] != dv2[i]) return false;
    }
    return true;
}

module.exports = {
  hacher, verifierHachage
}
