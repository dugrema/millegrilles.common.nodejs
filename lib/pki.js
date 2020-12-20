const debug = require('debug')('millegrilles:common:pki')
const crypto = require('crypto')
const forge = require('node-forge')
const stringify = require('json-stable-stringify')
const fs = require('fs')
const path = require('path')
const tmp = require('tmp')
const forgecommon = require('./forgecommon')
const { StringDecoder } = require('string_decoder')

const REPERTOIRE_CERTS_TMP = tmp.dirSync().name
debug("Repertoire temporaire certs : %s", REPERTOIRE_CERTS_TMP);

const PEM_CERT_DEBUT = '-----BEGIN CERTIFICATE-----'
const PEM_CERT_FIN = '-----END CERTIFICATE-----'

class MilleGrillesPKI {
  // Classe qui supporte des operations avec certificats et cles privees.

  constructor(certs) {
    this.idmg = null

    // Cle pour cert
    this.cle = null
    this.password = null  // Mot de passe pour la cle, optionnel

    // Liste de certificats de la chaine
    this.chaineCertificatsList = null

    // Contenu format texte PEM
    this.chainePEM = null
    this.hotePEM = null  // Chaine XS pour connexion middleware
    this.hoteCA = null
    this.ca = null
    this.fingerprint = null
    this.fingerprintSha256B64 = null

    this.caIntermediaires = []

    // Objets node-forge
    this.certPEM = null
    this.cleForge = null  // Objet cle charge en memoire (forge)
    this.cert = null      // Objet certificat charge en memoire (forge)
    this.caForge = null   // CA (certificat de MilleGrille)
    this.caStore = null   // CA store pour valider les chaines de certificats

    this.cacheCertsParFingerprint = {}  // Cle : fingerprint sha 256, value = [...certForge]

    this.algorithm = 'aes256'
    this.rsaAlgorithm = 'RSA-OAEP'
  }

  async chargerPEMs(certs) {

    // Cle pour cert
    this.cle = certs.key
    this.password = certs.password  // Mot de passe pour la cle, optionnel

    // Contenu format texte PEM
    this.chainePEM = certs.cert
    this.hotePEM = certs.hote || certs.cert  // Chaine XS pour connexion middleware
    this.hoteCA = certs.hoteMillegrille || certs.millegrille
    this.ca = certs.millegrille

    // Preparer repertoire pour sauvegarder PEMS
    fs.mkdir(REPERTOIRE_CERTS_TMP, {recursive: true, mode: 0o700}, e=>{
      if(e) {
        throw new Error(e)
      }
    });

    // Charger le certificat pour conserver commonName, fingerprint
    await this.chargerCertificats(certs)
    this._verifierCertificat()

    let cle = this.cle
    if(this.password) {
      debug("Cle chiffree")
      this.cleForge = forge.pki.decryptRsaPrivateKey(cle, this.password)
      // Re-exporter la cle en format PEM dechiffre (utilise par RabbitMQ)
      this.cle = forge.pki.privateKeyToPem(this.cleForge)
    } else {
      this.cleForge = forge.pki.privateKeyFromPem(cle)
    }

  }

  _verifierCertificat() {
    this.getFingerprint()
  }

  async chargerCertificats(certPems) {

    // Charger certificat local
    var certs = splitPEMCerts(certPems.cert)
    this.chaineCertificatsList = certs
    debug(certs)
    this.certPEM = certs[0]

    let parsedCert = this.chargerCertificatPEM(this.certPEM)

    this.idmg = parsedCert.issuer.getField("O").value
    debug("IDMG %s", this.idmg)

    const {fingerprint, fingerprintSha256B64} = getCertificateFingerprints(parsedCert)
    this.fingerprint = fingerprint
    this.fingerprintSha256B64 = fingerprintSha256B64
    this.cert = parsedCert
    this.commonName = parsedCert.subject.getField('CN').value

    // Sauvegarder certificats intermediaires
    const certsChaineCAList = certs.slice(1)
    const certsIntermediaires = []
    for(let idx in certsChaineCAList) {
      var certIntermediaire = certsChaineCAList[idx]
      let intermediaire = this.chargerCertificatPEM(certIntermediaire)
      certsIntermediaires.push(intermediaire)
    }
    this.caIntermediaires = certsIntermediaires

    // Creer le CA store pour verifier les certificats.
    let parsedCACert = this.chargerCertificatPEM(this.ca)
    this.caForge = parsedCACert
    this.caStore = forge.pki.createCaStore([parsedCACert])

  }

  chargerCertificatPEM(pem) {
    let parsedCert = forge.pki.certificateFromPem(pem);
    return parsedCert;
  }

  getFingerprint() {
    return this.fingerprint;
  }

  getFingerprintSha256B64() {
    return this.fingerprintSha256B64;
  }

  getCommonName() {
    return this.commonName;
  }

  signerTransaction(transaction) {

    let signature = 'N/A';
    const sign = crypto.createSign('SHA512');

    // Stringify en json trie
    let transactionJson = stringify(transaction);

    // Creer algo signature et signer
    sign.write(transactionJson);
    let parametresSignature = {
      "key": this.cle,
      "padding": crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 64,  // 64 bytes pour supporter iPhone max
    }
    signature = sign.sign(parametresSignature, 'base64');

    return signature;
  }

  hacherTransaction(transaction) {
    let hachage_transaction = 'N/A';
    const hash = crypto.createHash('sha256');

    // Copier transaction sans l'entete
    let copie_transaction = {};
    for(let elem in transaction) {
      if (elem !== 'en-tete' && !elem.startsWith('_')) {
        copie_transaction[elem] = transaction[elem];
      }
    }

    // Stringify en json trie
    let transactionJson = stringify(copie_transaction);

    // Creer algo signature et signer
    hash.write(transactionJson, 'utf-8');

    hachage_transaction = 'sha256_b64:' + hash.digest('base64')

    return hachage_transaction;
  }

  preparerMessageCertificat() {
    // Retourne un message qui peut etre transmis a MQ avec le certificat
    // utilise par ce noeud. Sert a verifier la signature des transactions.
    const certificatBuffer = this.certPEM;

    let transactionCertificat = {
        fingerprint: this.fingerprint,
        fingerprint_sha256_b64: this.fingerprintSha256B64,
        chaine_pem: this.chaineCertificatsList,
    }

    return transactionCertificat;
  }

  crypterContenu(certificat, contenu) {
    // Crypte un dict en JSON et retourne la valeur base64 pour
    // le contenu et la cle secrete cryptee.
    return this._creerCipherKey(certificat).then(({cipher, encryptedSecretKey, iv}) => {
      // debug("CRYPTER CONTENU!")
      let contenuString = JSON.stringify(contenu)

      let contenuCrypte = cipher.update(iv, 'bin', 'base64')
      contenuCrypte += cipher.update(contenuString, 'utf8', 'base64')
      contenuCrypte += cipher.final('base64')

      return {contenuCrypte, encryptedSecretKey, iv}
    })
  }

  async decrypterAsymetrique(contenuSecret) {
    // debug("CONTENU SECRET CHIFFRE : " + contenuSecret)
    let cleSecrete = forge.util.decode64(contenuSecret);

    // Decrypter la cle secrete avec notre cle privee
    var decryptedSecretKey = this.cleForge.decrypt(cleSecrete, 'RSA-OAEP', {
      md: forge.md.sha256.create(),
      mgf1: {
        md: forge.md.sha256.create()
      }
    });
    return decryptedSecretKey;
  }

  _creerCipherKey(certificat) {
    let promise = new Promise((resolve, reject) => {
      this.genererKeyAndIV((err, {key, iv})=>{
        if(err) {
          reject(err);
        }

        var cipher = crypto.createCipheriv(this.algorithm, key, iv);

        // Encoder la cle secrete
        var encryptedSecretKey = this.crypterContenuAsymetric(certificat.publicKey, key);
        iv = iv.toString('base64');

        resolve({cipher, encryptedSecretKey, iv});

      });
    });

    return promise;
  }

  crypterContenuAsymetric(publicKey, contentToEncrypt) {
    var keyByteString = forge.util.bytesToHex(contentToEncrypt);
    var encryptedContent = publicKey.encrypt(keyByteString, this.rsaAlgorithm, {
      md: forge.md.sha256.create(),
      mgf1: {
        md: forge.md.sha256.create()
      }
    });

    encryptedContent = forge.util.encode64(encryptedContent);
    return encryptedContent;
  }

  async creerCipherChiffrageAsymmetrique(certificats) {

    const keyIv = await new Promise((resolve, reject) => {
      this.genererKeyAndIV((err, keyIv)=>{
        if(err) return reject(err)
        resolve(keyIv)
      })
    })

    const cipher = crypto.createCipheriv(this.algorithm, keyIv.key, keyIv.iv)

    // Encoder la cle secrete
    const iv = keyIv.iv.toString('base64')

    const certClesChiffrees = {}
    certificats.forEach(certs=>{
      const certPem = certs[0]
      const cert = this.chargerCertificatPEM(certPem)
      const fingerprint = getCertificateFingerprintB64(cert)
      var encryptedSecretKey = this.crypterContenuAsymetric(cert.publicKey, keyIv.key);
      certClesChiffrees[fingerprint] = encryptedSecretKey
    })

    return({cipher, certClesChiffrees, iv})
  }

  async dechiffrerContenuAsymetric(cleSecrete, iv, contenuChiffre) {
    debug("dechiffrerContenuAsymetric: Cle secrete: %s\nIV: %s, contenuChiffre: %O", cleSecrete, iv, contenuChiffre)
    const cleSecreteDechiffree = await this.decrypterAsymetrique(cleSecrete)
    debug("Cle secrete dechiffree : %O", cleSecreteDechiffree)

    // const cleSecreteDechiffreeBytes = Buffer.from(cleSecreteDechiffree, 'hex')
    // const cleSecreteDechiffreeBytes = Buffer.from(cleSecreteDechiffree)
    const cleSecreteDechiffreeBytes = str2ab(cleSecreteDechiffree)

    const ivBytes = Buffer.from(iv, 'base64')
    const bytesChiffreSymmetrique = Buffer.from(contenuChiffre.secret_chiffre || contenuChiffre, 'base64')

    debug("Creer decipher secretKey: " + cleSecreteDechiffreeBytes.toString('base64') + ", iv: " + ivBytes.toString('base64'));
    var decipher = crypto.createDecipheriv('aes-256-cbc', cleSecreteDechiffreeBytes, ivBytes);

    // console.debug("Decrypter " + contenuCrypte.toString('base64'));
    const decoder = new StringDecoder('utf8');
    let contenuDecrypte = decipher.update(bytesChiffreSymmetrique, 'base64')
    let ivDechiffre = contenuDecrypte.slice(0, 16)
    debug("IV Dechiffre : %O\nIV recu: %O", ivDechiffre, ivBytes)

    // Comparer le IV pour s'assurer que le dechiffrage est correct
    if( ! forgecommon.comparerArraybuffers(ivDechiffre, ivBytes) ) {
      throw new Error("Dechiffrage - IV ne correspond pas")
    }

    var contenuDechiffreString = decoder.write(contenuDecrypte.slice(16))
    contenuDechiffreString += decoder.write(decipher.final())

    return contenuDechiffreString
  }

  async creerCipherChiffrageAsymmetrique(certificats) {

    const keyIv = await new Promise((resolve, reject) => {
      this.genererKeyAndIV((err, keyIv)=>{
        if(err) return reject(err)
        resolve(keyIv)
      })
    })

    const cipher = crypto.createCipheriv(this.algorithm, keyIv.key, keyIv.iv)

    // Encoder la cle secrete
    const iv = keyIv.iv.toString('base64')

    const certClesChiffrees = {}
    certificats.forEach(certs=>{
      const certPem = certs[0]
      const cert = this.chargerCertificatPEM(certPem)
      const fingerprint = getCertificateFingerprintB64(cert)
      var encryptedSecretKey = this.crypterContenuAsymetric(cert.publicKey, keyIv.key);
      certClesChiffrees[fingerprint] = encryptedSecretKey
    })

    return({cipher, certClesChiffrees, iv})
  }

  genererKeyAndIV(cb) {
    var lenBuffer = 16 + 32;
    crypto.pseudoRandomBytes(lenBuffer, (err, pseudoRandomBytes) => {
      // Creer deux buffers, iv (16 bytes) et password (24 bytes)
      var iv = pseudoRandomBytes.slice(0, 16);
      var key = pseudoRandomBytes.slice(16, pseudoRandomBytes.length);
      cb(err, {key: key, iv: iv});
    });
  }

  async genererRandomBytes(nbBytes, opts) {
    if(!opts) opts = {}
    return new Promise((resolve, reject)=>{
      crypto.pseudoRandomBytes(nbBytes, (err, pseudoRandomBytes) => {
        // Creer deux buffers, iv (16 bytes) et password (24 bytes)
        if(err) reject(err)
        else {
          if(opts.base64) {
            // Encoder les bytes en base64
            const b64Content = pseudoRandomBytes.toString('base64')
            resolve(b64Content)
          } else {
            resolve(pseudoRandomBytes)
          }
        }
      });
    })
  }

  extraireClePubliqueFingerprint(certificat) {

    const fingerprint = getCertificateFingerprint(certificat);

    const clePubliquePEM = forge.pki.publicKeyToPem(certificat.publicKey);

    var clePublique = clePubliquePEM
      .replace('-----BEGIN PUBLIC KEY-----', '')
      .replace('-----END PUBLIC KEY-----', '');

    // Remplacer les \n pour mettre la cle sur une seule ligne
    clePublique = clePublique.split('\n').join('');

    return {clePublique, fingerprint};
  }

  // Sauvegarde un message de certificat en format JSON
  async sauvegarderMessageCertificat(message, fingerprintSha256B64) {

    // Convertir fingerprint de b64 vers hex (b64 pas safe comme nom de fichier)
    const fingerprintBytes = forge.util.decode64(fingerprintSha256B64)
    const fingerprint = forge.util.bytesToHex(fingerprintBytes)
    const fichier = path.join(REPERTOIRE_CERTS_TMP, fingerprint + '.json')

    let fichierExiste = fingerprintSha256B64 && await new Promise((resolve, reject)=>{
      try {
        debug("Verification existance fichier certificat %s => %s", fingerprintSha256B64, fingerprint)

        // Verifier si le fichier existe deja
        fs.access(fichier, fs.constants.F_OK, (err) => {
          let existe = ! err;
          debug("Fichier existe? %s : %s", existe, fichier)
          resolve(existe);
        })
      } catch (err) {
        return reject(err)
      }
    })

    if( ! fichierExiste ) {
      let json_message = JSON.parse(message);
      let chaine_pem = json_message.chaine_pem || json_message.resultats.chaine_pem

      // Verifier la chain de certificats
      const store = new forgecommon.CertificateStore(this.ca)
      if(store.verifierChaine(chaine_pem)) {
        let certificat = this.chargerCertificatPEM(chaine_pem[0])
        let {fingerprintSha256} = getCertificateFingerprints(certificat)

        const chaineCerts = chaine_pem.map(pem=>{
          return this.chargerCertificatPEM(pem)
        })
        this.cacheCertsParFingerprint[fingerprintSha256] = chaineCerts

        // Sauvegarder sur disque
        await new Promise((resolve, reject)=>{
          try {
            fs.writeFile(fichier, chaine_pem.join('\n'), {'encoding': 'utf-8', flag: 'wx'}, err=>{
              if(err) reject(err)
              debug("Fichier certificat sauvegarde : %s", fichier);
              resolve()
            })
          } catch(err) {
            reject(err)
          }
        })
      } else {
        throw new Error(`Erreur validation certificat recu : ${json_message.fingerprint_sha256_b64}`)
      }
    } else {
      const fingerprintBytes = forge.util.decode64(fingerprintSha256B64)
      const fingerprint = forge.util.bytesToHex(fingerprintBytes)
      debug("Fichier certificat existe deja pour certificat %s (%s.json)", fingerprintSha256B64, fingerprint)
    }
  }

  // Charge la chaine de certificats pour ce fingerprint
  async getCertificate(fingerprint) {
    let format = 'hex', fingerprintEffectif = fingerprint
    let indexOfColon = fingerprint.indexOf(':')
    if(indexOfColon > -1) {
      // Format est sha256_b64:H7coR5Pg0ncohF9aELaiLs9hD4WqQUyTgAsfR8+cB2k=
      const fingerprintSplit = fingerprint.split(':')
      format = fingerprintSplit[0]
      fingerprintEffectif = fingerprintSplit[1]
    }
    if(format.indexOf('_b64') > -1) {
      // Convertir en hex pour nom de fichier
      const fingerprintBytes = forge.util.decode64(fingerprintEffectif)
      fingerprintEffectif = forge.util.bytesToHex(fingerprintBytes)
    }

    // Tenter de charger le certificat a partir du cache memoire
    debug("Fingerprint format %s, effectif : %s", format, fingerprintEffectif)
    var certificat = this.cacheCertsParFingerprint[fingerprintEffectif]

    if(certificat) {
      return certificat
    } else {
      // Verifier si le certificat existe sur le disque
      return await new Promise((resolve, reject)=>{
        let fichier = path.join(REPERTOIRE_CERTS_TMP, fingerprintEffectif + '.json')
        fs.readFile(fichier, 'utf8', (err, data)=>{
          if(err) return reject(err)
          if(!data) return reject(new Error("Aucune donnee pour certificat " + fingerprint)) // No data

          try {
            const listePems = splitPEMCerts(data)
            const chaine = listePems.map(pem=>{
              return this.chargerCertificatPEM(pem)
            })

            const fingerprintsCalcules = getCertificateFingerprints(chaine[0]);
            const fingerprintCalcule = 'sha256_b64:' + fingerprintsCalcules.fingerprintSha256B64
            var fingerprintMatch = false
            if(format === 'sha256_b64' && fingerprintCalcule === fingerprint) {
              fingerprintMatch = true
            }
            if( ! fingerprintMatch ) {
              // Supprimer fichier invalide
              // fs.unlink(fichier, ()=>{});
              return reject('Fingerprint ' + fingerprintCalcule + ' ne correspond pas au fichier : ' + fingerprint + '.json. Fichier supprime.');
            }

            // Valider le certificat avec le store
            let valide = true
            try {
              forge.pki.verifyCertificateChain(this.caStore, chaine)
            } catch (err) {
              valide = false
              debug('Certificate verification failure: %s', JSON.stringify(err, null, 2))
            }

            if(valide) {
              this.cacheCertsParFingerprint[fingerprintCalcule] = chaine
            } else {
              return reject(new Error("Certificat local invalide pour " + fingerprint))
            }

            resolve(chaine)

          } catch(err) {
            return reject(err)
          }

        })
      })
    }

  }

  // Verifie la signature d'un message
  // Retourne vrai si le message est valide, faux si invalide.
  async verifierSignatureMessage(message) {
    let fingerprint = message['en-tete']['fingerprint_certificat'];
    let signatureBase64 = message['_signature'];
    let signature = Buffer.from(signatureBase64, 'base64');

    let certificatChaine = null
    try {
      // Tenter de charger le certificat localement
      debug("Tenter de charger le certificat localement : " + fingerprint)
      certificatChaine = await this.getCertificate(fingerprint)
      debug("Certifcat charge")
    } catch (err) {
      debug("warning - Erreur chargement chaine localement, verifier d'autres methodes de chargement\n%O", err)
    }

    if( ! certificatChaine && message['_certificat']) {
      // Verifier la chaine de certificats inclue avec le message
      const chaineInclue = message['_certificat']
      const store = new forgecommon.CertificateStore(this.ca)
      if(store.verifierChaine(chaineInclue)) {
        certificatChaine = [this.chargerCertificatPEM(chaineInclue[0])]
      }
    }

    if( ! certificatChaine ) {
      debug("Certificat inconnu : " + fingerprint)
      throw new CertificatInconnu("Certificat inconnu : " + fingerprint)
    }
    const certificat = certificatChaine[0]

    let messageFiltre = {};
    for(let cle in message) {
      if( ! cle.startsWith('_') ) {
        messageFiltre[cle] = message[cle];
      }
    }
    // Stringify en ordre (stable)
    messageFiltre = stringify(messageFiltre);

    let keyLength = certificat.publicKey.n.bitLength();
    // Calcul taille salt:
    // http://bouncy-castle.1462172.n4.nabble.com/Is-Bouncy-Castle-SHA256withRSA-PSS-compatible-with-OpenSSL-RSA-PSS-padding-with-SHA256-digest-td4656843.html
    // Changement a 64 pour supporter iPhone
    let saltLength = 64  // (keyLength - 512) / 8 - 2;

    var pss = forge.pss.create({
      md: forge.md.sha512.create(),
      mgf: forge.mgf.mgf1.create(forge.md.sha512.create()),
      saltLength,
      // optionally pass 'prng' with a custom PRNG implementation
    });
    var md = forge.md.sha512.create();
    md.update(messageFiltre, 'utf8');

    try {
      var publicKey = certificat.publicKey
      let valide = publicKey.verify(md.digest().getBytes(), signature, pss)
      return valide
    } catch (err) {
      debug("Erreur verification signature")
      debug(err)
      return false
    }

  }

  // Calcule le IDMG a partir d'un certificat PEM
  calculerIdmg(certificatPEM) {
    const cert = forge.pki.certificateFromPem(certificatPEM)

    const fingerprint = forge.md.sha512.sha224.create()
      .update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())
      .digest()
      .toHex()
    const buffer = Buffer.from(fingerprint, 'hex')
    const idmg = base58.encode(buffer)

    return idmg
  }

  signerContenuString(contenuString) {
    return forgecommon.signerContenuString(this.cleForge, contenuString)
  }

  getChainePems() {
    const pems = this.chainePEM
    return splitPEMCerts(pems)
  }

}

function getCertificateFingerprint(cert) {
  const fingerprint = forge.md.sha1.create()
    .update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())
    .digest()
    .toHex();
  return fingerprint
}

function getCertificateFingerprintB64(cert) {
  const digest = forge.md.sha1.create()
    .update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())
    .digest()

  const fingerprintBase64 = forge.util.encode64(digest.getBytes())
  return fingerprintBase64
}

function getCertificateFingerprints(cert) {
  const digestSha256Bytes = forge.md.sha256.create()
    .update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())
    .digest()
    .getBytes()
  const fingerprint = getCertificateFingerprint(cert)
  const fingerprintSha256 = forge.util.bytesToHex(digestSha256Bytes)
  const fingerprintSha256B64 = forge.util.encode64(digestSha256Bytes)

  return {fingerprint, fingerprintSha256, fingerprintSha256B64}
}

function splitPEMCerts(certs) {
  var splitCerts = certs.split(PEM_CERT_DEBUT).map(c=>{
    return PEM_CERT_DEBUT + c
  })
  return splitCerts.slice(1)
}

function str2ab(str) {

  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return bufView;

}

class CertificatInconnu extends Error {
  constructor(message) {
    super(message);
    this.inconnu = true;
  }
}

module.exports = MilleGrillesPKI
