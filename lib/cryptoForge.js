const {pki, md, asn1} = require('node-forge');
const base58 = require('base-58')

const BEGIN_PUBLIC_KEY  = "-----BEGIN PUBLIC KEY-----",
      END_PUBLIC_KEY    = "-----END PUBLIC KEY-----",
      BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----",
      END_PRIVATE_KEY   = "-----END PRIVATE KEY-----"

export function chiffrerPrivateKeyPEM(privateKeyPEM, motDePasse) {

  const privateKey = pki.privateKeyFromPem(privateKeyPEM);
  var pem = pki.encryptRsaPrivateKey(privateKey, motDePasse);
  // console.debug(pem);

  return pem

}

export function enveloppePEMPublique(clePubliqueStr) {
  return [BEGIN_PUBLIC_KEY, clePubliqueStr, END_PUBLIC_KEY].join('\n')
}

export function enveloppePEMPrivee(clePriveeStr) {
  return [BEGIN_PRIVATE_KEY, clePriveeStr, END_PRIVATE_KEY].join('\n')
}

// Genere un nouveau certificat de MilleGrille a partir d'un keypair
export async function genererCertificatMilleGrille(clePriveePEM, clePubliquePEM) {

  console.debug("Creation nouveau certificat de MilleGrille")
  console.debug("Cle Publique : %s", clePubliquePEM)

  const clePublique = pki.publicKeyFromPem(clePubliquePEM)
  const clePrivee = pki.privateKeyFromPem(clePriveePEM)

  const cert = pki.createCertificate()
  cert.publicKey = clePublique
  cert.serialNumber = genererRandomSerial()
  cert.validity.notBefore = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)

  var attrs = [{
    name: 'commonName',
    value: 'Racine'
  },{
    name: 'organizationName',
    value: 'MilleGrille'
  }]
  cert.setSubject(attrs)
  cert.setIssuer(attrs)  // Self, genere un certificat self-signed (racine)
  cert.setExtensions([{
    name: 'basicConstraints',
    critical: true,
    cA: true,
    pathLenConstraint: 5,
  }, {
    name: 'subjectKeyIdentifier'
  }, {
    name: 'authorityKeyIdentifier',
    keyIdentifier: true,
  }])

  // Signer certificat
  // cert.md = md.sha512.create()
  await cert.sign(clePrivee, md.sha512.create())

  // Exporter sous format PEM
  var pem = pki.certificateToPem(cert)

  var idmg = calculerIdmg(pem)

  return {cert, pem, idmg}

}

// Genere un nouveau certificat de MilleGrille a partir d'un keypair
export async function genererCertificatIntermediaire(idmg, certificatRacine, cleSignateurPEM, clePubliquePEM) {

  console.debug("Creation nouveau certificat intermediaire")
  console.debug("Cle Publique : %s", clePubliquePEM)

  const clePublique = pki.publicKeyFromPem(clePubliquePEM)
  const cleSignateur = pki.privateKeyFromPem(cleSignateurPEM)

  const cert = pki.createCertificate()
  cert.publicKey = clePublique
  cert.serialNumber = genererRandomSerial()
  cert.validity.notBefore = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)

  var attrs = [{
    name: 'commonName',
    value: idmg
  },{
    name: 'organizationalUnitName',
    value: 'MilleGrille'
  },{
    name: 'organizationName',
    value: idmg
  }]
  cert.setSubject(attrs)
  cert.setIssuer(certificatRacine.subject.attributes)
  cert.setExtensions([{
    name: 'basicConstraints',
    critical: true,
    cA: true,
    pathLenConstraint: 4,
  }, {
    name: 'subjectKeyIdentifier'
  }, {
    name: 'authorityKeyIdentifier',
    keyIdentifier: certificatRacine.generateSubjectKeyIdentifier().data,
  }])

  // Signer certificat
  // cert.md = md.sha512.create()
  await cert.sign(cleSignateur, md.sha512.create())

  // Exporter sous format PEM
  var pem = pki.certificateToPem(cert)

  return {cert, pem}

}

// Genere un nouveau certificat de MilleGrille a partir d'un keypair
export async function genererCertificatFin(idmg, certificatIntermediaire, cleSignateurPEM, clePubliquePEM) {

  console.debug("Creation nouveau certificat de fin")
  console.debug("Cle Publique : %s", clePubliquePEM)

  const clePublique = pki.publicKeyFromPem(clePubliquePEM)
  const cleSignateur = pki.privateKeyFromPem(cleSignateurPEM)

  const cert = pki.createCertificate()
  cert.publicKey = clePublique
  cert.serialNumber = genererRandomSerial()
  cert.validity.notBefore = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)

  var attrs = [{
    name: 'commonName',
    value: 'navigateur'
  },{
    name: 'organizationalUnitName',
    value: 'navigateur'
  },{
    name: 'organizationName',
    value: idmg
  }]
  cert.setSubject(attrs)
  cert.setIssuer(certificatIntermediaire.subject.attributes)
  cert.setExtensions([{
    name: 'basicConstraints',
    critical: true,
    cA: false,
  }, {
    name: 'subjectKeyIdentifier'
  }, {
    name: 'authorityKeyIdentifier',
    keyIdentifier: certificatIntermediaire.generateSubjectKeyIdentifier().data,
  },{
    name: 'keyUsage',
    keyCertSign: false,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  }])

  // Signer certificat
  // cert.md = md.sha512.create()
  await cert.sign(cleSignateur, md.sha512.create())

  // Exporter sous format PEM
  var pem = pki.certificateToPem(cert)

  return {cert, pem}

}

export class CertificateStore {
  constructor(parsedCACert) {
    this.caStore = pki.createCaStore([parsedCACert])
  }

  verifierChaine(chainePEM) {

    // Charger PEMs vers format forge
    const chaineCerts = chainePEM.map(item=>{
      return pki.certificateFromPem(item)
    })

    let valide = true;
    try {
      pki.verifyCertificateChain(this.caStore, chaineCerts);
    } catch (err) {
      valide = false;
      console.warn('Certificate verification failure: %s', JSON.stringify(err, null, 2));
    }

    return valide
  }

}

// Calcule le IDMG a partir d'un certificat PEM
export function calculerIdmg(certificatPEM) {
  const cert = pki.certificateFromPem(certificatPEM)

  const fingerprint = md.sha512.sha224.create()
    .update(asn1.toDer(pki.certificateToAsn1(cert)).getBytes())
    .digest()
    .toHex()
  const buffer = Buffer.from(fingerprint, 'hex')
  const idmg = base58.encode(buffer)

  return idmg
}

export function matchCertificatKey(certificatPEM, keyPEM) {
  const cert = pki.certificateFromPem(certificatPEM)
  const key = pki.privateKeyFromPem(keyPEM)

  // console.debug("Cert, cle")
  // console.debug(cert.publicKey.n)
  // console.debug(key.n)

  const cleCertMatch = cert.publicKey.n.compareTo(key.n) === 0
  // console.debug("Match : %s", cleCertMatch)

  return cleCertMatch
}

function genererRandomSerial() {
  const serial = '' + Math.floor(Math.random() * 10000000000000000000)
  if(serial.length < 2) {
    serial = '0' + serial
  }
  return serial
}
