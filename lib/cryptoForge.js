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
  console.debug("Cle Privee : %s", clePriveePEM)

  const clePublique = pki.publicKeyFromPem(clePubliquePEM)
  const clePrivee = pki.privateKeyFromPem(clePriveePEM)

  const cert = pki.createCertificate()
  cert.publicKey = clePublique
  cert.serialNumber = '01'
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
  console.debug("Cle Privee pour signature : %s", cleSignateurPEM)

  const clePublique = pki.publicKeyFromPem(clePubliquePEM)
  const cleSignateur = pki.privateKeyFromPem(cleSignateurPEM)

  const cert = pki.createCertificate()
  cert.publicKey = clePublique
  cert.serialNumber = '01'
  cert.validity.notBefore = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)

  var attrs = [{
    name: 'commonName',
    value: idmg
  },{
    name: 'organizationName',
    value: 'MilleGrille'
  }]
  cert.setSubject(attrs)
  cert.setIssuer(certificatRacine.subject.attributes)
  cert.setExtensions([{
    name: 'basicConstraints',
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
