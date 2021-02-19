const {pki, md, asn1} = require('node-forge')
const multihash = require('multihashes')
const multibase = require('multibase')

const {calculerDigest} = require('./hachage')

async function encoderIdmg(pem, opts) {
  opts = opts || {}
  const version = opts.version || 2
  const hashingCode = opts.hash || 'sha2-256'
  const encoding = 'base58btc'

  const cert = pki.certificateFromPem(pem)
  const certBuffer = asn1.toDer(pki.certificateToAsn1(cert)).getBytes()

  const digestView = await calculerDigest(certBuffer, hashingCode)
  const mhValeur = multihash.encode(digestView, hashingCode)

  console.debug("DIGEST multihash : %O", mhValeur)

  const date_expiration = cert.validity.notAfter
  const dateExpEpoch_1000 = Math.ceil(date_expiration.getTime() / 1000000)
  const bufferExpiration = new ArrayBuffer(4)
  const view32Uint = new Uint32Array(bufferExpiration)
  view32Uint[0] = dateExpEpoch_1000

  // Set version courante dans le premier byte
  const arrayBufferIdmg = new ArrayBuffer(5 + mhValeur.length)
  const viewUint8Idmg = new Uint8Array(arrayBufferIdmg)
  viewUint8Idmg[0] = version

  // Set date expiration du cert dans bytes 1-5
  viewUint8Idmg.set(new Uint8Array(bufferExpiration), 1)

  // Set multihash dans bytes 5+
  viewUint8Idmg.set(mhValeur, 5)

  // Encoder en multibase
  var mbValeur = multibase.encode(encoding, viewUint8Idmg)
  mbValeur = String.fromCharCode.apply(null, mbValeur)

  return mbValeur
}

module.exports = {
  encoderIdmg,
}
