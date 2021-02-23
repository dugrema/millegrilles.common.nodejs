// Module de hachage, utilise subtle dans le navigateur lorsque c'est approprie
// Fallback sur node-forge
const multihash = require('multihashes')
const multibase = require('multibase')
const {util: forgeUtil, md: forgeMd} = require('node-forge')

// Charger subtle si disponible dans le navigateur
function detecterSubtle() {
  if( typeof(window) !== 'undefined' && window.crypto) return window.crypto.subtle
  return null
}
const _subtle = detecterSubtle()

async function hacher(valeur, opts) {
  if(!opts) opts = {}
  const hashingCode = opts.hashingCode || 'sha2-512'
  const encoding = opts.encoding || 'base58btc'

  // Convertir la valeur en ArrayBuffer
  // console.debug(`Type de la valeur : ${typeof(valeur)}`)

  // Hacher la valeur
  const digestView = await calculerDigest(valeur, hashingCode)

  // Creer le multihash
  const mhValeur = multihash.encode(digestView, hashingCode)

  // Encoder en base58btc avec multibase
  var mbValeur = multibase.encode(encoding, mhValeur)
  mbValeur = String.fromCharCode.apply(null, mbValeur)

  return mbValeur
}

async function calculerDigest(valeur, hashingCode) {
  let digest
  if(_subtle) {
    // Utiliser subtle dans le navigateur (native)
    digest = await _calculerHachageSubtle(valeur, {hash: hashingCode})
  } else {
    // Fallback sur node-forge
    digest = _calculerHachageForge(valeur, {hash: hashingCode})
  }
  const digestView = new Uint8Array(digest)
  return digestView
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

  // console.debug("Hachage subtle avec algo : %O", hachageSubtle)
  return _subtle.digest(hachageSubtle, valeur)  // Promise
}

function _calculerHachageForge(valeur, opts) {
  var hachage = opts.hash || 'sha2-512'

  const fonctionHachage = _mapFonctionHachageForge(hachage)

  if(typeof(valeur) === 'string') {
    valeur = forgeUtil.encodeUtf8(valeur)
  } else {
    // Convertir AB vers byte string
    valeur = forgeUtil.createBuffer(valeur, 'raw').getBytes()
  }

  // console.debug("Valeur : %O", valeur)

  var resultatHachage = fonctionHachage.create()
    .update(valeur)
    .digest()
    .getBytes()

  return Buffer.from(resultatHachage, 'binary')
}

function _mapFonctionHachageForge(hachage) {
  let fonctionHachage
  if(hachage === 'sha2-512') {
    fonctionHachage = forgeMd.sha512
  } else if(hachage === 'sha2-256') {
    fonctionHachage = forgeMd.sha256
  } else {
    throw new Error(`Fonction hachage non supportee : ${hachage}`)
  }
  return fonctionHachage
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

  if( comparerArraybuffers(digest, digestCalcule) ) {
    return true
  } else {
    throw new Error("Erreur hachage, mismatch")
  }
}

function comparerArraybuffers(buf1, buf2) {
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

class Hacheur {
  constructor(opts) {
    opts = opts || {}
    this.encoding = opts.encoding || 'base58btc'
    this.hashingCode = opts.hash || 'sha2-512'
    this._digest = null
    this.mh = null

    const fonctionHachage = _mapFonctionHachageForge(this.hashingCode)
    this._digester = fonctionHachage.create()
  }

  update(data) {
    if(typeof(data) === 'string') {
      data = forgeUtil.encodeUtf8(data)
    } else {
      // Convertir AB vers byte string
      data = forgeUtil.createBuffer(data, 'raw').getBytes()
    }
    this._digester.update(data)
  }

  digest() {
    if(this._digest) return this._digest

    var resultatHachage = this._digester.digest().getBytes()
    this._digest = Buffer.from(resultatHachage, 'binary')
    this._digester = null
    return this._digest
  }

  finalize() {
    if(this.mh) return this.mh

    const digest = this.digest()
    const digestView = new Uint8Array(digest)

    // Creer le multihash
    const mhValeur = multihash.encode(digestView, this.hashingCode)

    // Encoder en base58btc avec multibase
    var mbValeur = multibase.encode(this.encoding, mhValeur)
    this.mh = String.fromCharCode.apply(null, mbValeur)

    return this.mh
  }
}

class VerificateurHachage {

  constructor(hachage) {
    const mb = multibase.decode(hachage)
    this.mh = multihash.decode(mb)

    // Creer contexte de hachage
    const hashingCode = this.mh.name
    const fonctionHachage = _mapFonctionHachageForge(hashingCode)
    this._digester = fonctionHachage.create()
  }

  update(data) {
    if(typeof(data) === 'string') {
      data = forgeUtil.encodeUtf8(data)
    } else {
      // Convertir AB vers byte string
      data = forgeUtil.createBuffer(data, 'raw').getBytes()
    }
    this._digester.update(data)
  }

  digest() {
    if(this._digest) return this._digest

    var resultatHachage = this._digester.digest().getBytes()
    this._digest = Buffer.from(resultatHachage, 'binary')
    this._digester = null
    return this._digest
  }

  verify() {
    var digestCalcule = this.digest()
    digestCalcule = new Uint8Array(digestCalcule)

    const digestRecu = this.mh.digest

    if( comparerArraybuffers(digestRecu, digestCalcule) ) {
      return true
    } else {
      throw new Error("Erreur hachage, mismatch")
    }
  }

}

module.exports = {
  hacher, verifierHachage, Hacheur, VerificateurHachage, calculerDigest,
  comparerArraybuffers
}
