const debug = require('debug')('millegrilles:common:pki')
const crypto = require('crypto')
const forge = require('node-forge')
const stringify = require('json-stable-stringify')
const fs = require('fs')
const path = require('path')
const tmp = require('tmp')
const { StringDecoder } = require('string_decoder')

const forgecommon = require('./forgecommon')
const {splitPEMCerts, FormatteurMessage} = require('./formatteurMessage')
const {verifierMessage} = require('./validateurMessage')
const {hacherCertificat} = require('./hachage')
const {creerCipher, dechiffrerCleSecreteForge, preparerCommandeMaitrecles} = require('./chiffrage')

// const REPERTOIRE_CERTS_TMP = tmp.dirSync().name
// debug("Repertoire temporaire certs : %s", REPERTOIRE_CERTS_TMP);

const PEM_CERT_DEBUT = '-----BEGIN CERTIFICATE-----'
const PEM_CERT_FIN = '-----END CERTIFICATE-----'
const EXPIRATION_CERTCACHE = 2 * 60000   // 2 minutes en millisecs

class MilleGrillesPKI {
  // Classe qui supporte des operations avec certificats et cles privees.

  constructor() {
    this.idmg = null

    // Cle pour cert
    this.cle = null
    this.password = null  // Mot de passe pour la cle, optionnel

    // Liste de certificats de la chaine
    // this.chaineCertificatsList = null

    // Contenu format texte PEM
    this.chainePEM = null
    // this.hotePEM = null  // Chaine XS pour connexion middleware
    // this.hoteCA = null
    this.ca = null
    this.fingerprint = null

    // this.caIntermediaires = []

    // Objets node-forge
    this.certPEM = null
    this.cleForge = null  // Objet cle charge en memoire (forge)
    this.cert = null      // Objet certificat charge en memoire (forge)
    this.caForge = null   // CA (certificat de MilleGrille)
    this.caStore = null   // CA store pour valider les chaines de certificats

    // Cle : fingerprintb58, value = { ts (date millisecs), chaineForge:[...certForge] }
    this.cacheCertsParFingerprint = {}

    // this.algorithm = 'aes256'
    // this.rsaAlgorithm = 'RSA-OAEP'

    // Gestionnaire de messages de certificats (optionnel)
    // Permet de faire des requetes pour aller chercher des nouveaux
    // certificats
    this.gestionnaireCertificatMessages = null

    this.formatteurMessage = null

    // Client redis pour caching - optionnel, permet de stocker les certificats
    this.redisClient = null

    this.intervalleMaintenanceCache = setInterval(()=>{this.maintenanceCache()}, 60000)
  }

  async initialiserPkiPEMS(certs) {

    // Cle pour cert
    this.cle = certs.key
    this.password = certs.password  // Mot de passe pour la cle, optionnel

    // Contenu format texte PEM
    this.chainePEM = certs.cert
    // this.hotePEM = certs.hote || certs.cert  // Chaine XS pour connexion middleware
    // this.hoteCA = certs.hoteMillegrille || certs.millegrille
    this.ca = certs.millegrille

    // DEPRECATED, remplace par redis
    // // Preparer repertoire pour sauvegarder PEMS
    // fs.mkdir(REPERTOIRE_CERTS_TMP, {recursive: true, mode: 0o700}, e=>{
    //   if(e) {
    //     throw new Error(e)
    //   }
    // });

    // Charger le certificat pour conserver commonName, fingerprint
    await this._initialiserStoreCa(certs)

    let cle = this.cle
    if(this.password) {
      debug("Cle chiffree")
      this.cleForge = forge.pki.decryptRsaPrivateKey(cle, this.password)
      // Re-exporter la cle en format PEM dechiffre (utilise par RabbitMQ, formatteur)
      this.cle = forge.pki.privateKeyToPem(this.cleForge)
    } else {
      this.cleForge = forge.pki.privateKeyFromPem(cle)
    }

    // Creer instance de formatteur de messages
    this.formatteurMessage = new FormatteurMessage(this.chainePEM, this.cle)
  }

  // _verifierCertificat() {
  //   this.getFingerprint()
  // }

  formatterMessage(message, domaineAction, opts) {
    // Retourner promise
    return this.formatteurMessage.formatterMessage(message, domaineAction, opts)
  }

  async verifierMessage(message) {
    // Trouver le certificat correspondant au message
    const fingerprint = message['en-tete'].fingerprint_certificat
    const chaine = message['_certificat']

    const opts = {}
    if(chaine) {
      // On a un certificat inline - on tente quand meme d'utiliser le cache
      opts.nowait = true
    }
    var chaineForge = null
    var _err = null
    try {
      chaineForge = await this.getCertificate(fingerprint, opts)
    } catch(err) {
      _err = err
    }

    if(!chaineForge) {
      if(!chaine) throw _err
      debug("Certificat non trouve localement, mais il est inline")
      await this.sauvegarderMessageCertificat({chaine_pem: chaine}, fingerprint)
      const certCache = this.cacheCertsParFingerprint[fingerprint]
      let chaineForge = null
      if(certCache) {
        chaineForge = certCache.chaineForge
        certCache.ts = new Date().getTime()  // Touch
      }
      debug("Certificat inline sauvegarde sous %s\n%O", fingerprint, chaineForge)
    }

    // Retourner promise
    const certificat = chaineForge[0]

    return verifierMessage(message, certificat)
  }

  async _initialiserStoreCa(certPems) {

    // Charger certificat local
    var certs = splitPEMCerts(certPems.cert)
    this.chaineCertificatsList = certs
    debug(certs)
    this.certPEM = certs[0]

    let parsedCert = forge.pki.certificateFromPem(this.certPEM)

    this.idmg = parsedCert.issuer.getField("O").value
    debug("IDMG %s", this.idmg)

    const fingerprint = await hacherCertificat(parsedCert)
    this.fingerprint = fingerprint
    this.cert = parsedCert
    this.commonName = parsedCert.subject.getField('CN').value

    // Sauvegarder certificats intermediaires
    const certsChaineCAList = certs.slice(1)
    const certsIntermediaires = []
    for(let idx in certsChaineCAList) {
      var certIntermediaire = certsChaineCAList[idx]
      let intermediaire = forge.pki.certificateFromPem(certIntermediaire)
      certsIntermediaires.push(intermediaire)
    }
    this.caIntermediaires = certsIntermediaires

    // Creer le CA store pour verifier les certificats.
    let parsedCACert = forge.pki.certificateFromPem(this.ca)
    this.caForge = parsedCACert
    this.caStore = forge.pki.createCaStore([parsedCACert])

  }

  // chargerCertificatPEM(pem) {
  //   let parsedCert = forge.pki.certificateFromPem(pem);
  //   return parsedCert;
  // }

  // getFingerprint() {
  //   return this.fingerprint;
  // }

  // getFingerprintSha256B64() {
  //   return this.fingerprintSha256B64;
  // }

  // getCommonName() {
  //   return this.commonName;
  // }

  // signerTransaction(transaction) {
  //
  //   let signature = 'N/A';
  //   const sign = crypto.createSign('SHA512');
  //
  //   // Stringify en json trie
  //   let transactionJson = stringify(transaction);
  //
  //   // Creer algo signature et signer
  //   sign.write(transactionJson);
  //   let parametresSignature = {
  //     "key": this.cle,
  //     "padding": crypto.constants.RSA_PKCS1_PSS_PADDING,
  //     saltLength: 64,  // 64 bytes pour supporter iPhone max
  //   }
  //   signature = sign.sign(parametresSignature, 'base64');
  //
  //   return signature;
  // }

  // hacherTransaction(transaction) {
  //   let hachage_transaction = 'N/A';
  //   const hash = crypto.createHash('sha256');
  //
  //   // Copier transaction sans l'entete
  //   let copie_transaction = {};
  //   for(let elem in transaction) {
  //     if (elem !== 'en-tete' && !elem.startsWith('_')) {
  //       copie_transaction[elem] = transaction[elem];
  //     }
  //   }
  //
  //   // Stringify en json trie
  //   let transactionJson = stringify(copie_transaction);
  //
  //   // Creer algo signature et signer
  //   hash.write(transactionJson, 'utf-8');
  //
  //   hachage_transaction = 'sha256_b64:' + hash.digest('base64')
  //
  //   return hachage_transaction;
  // }

  preparerMessageCertificat() {
    // Retourne un message qui peut etre transmis a MQ avec le certificat
    // utilise par ce noeud. Sert a verifier la signature des transactions.
    let transactionCertificat = {
        fingerprint: this.fingerprint,
        chaine_pem: this.chaineCertificatsList,
    }

    return transactionCertificat;
  }

  // crypterContenu(certificat, contenu) {
  //   // Crypte un dict en JSON et retourne la valeur base64 pour
  //   // le contenu et la cle secrete cryptee.
  //   return this._creerCipherKey(certificat).then(({cipher, encryptedSecretKey, iv}) => {
  //     // debug("CRYPTER CONTENU!")
  //     let contenuString = JSON.stringify(contenu)
  //
  //     let contenuCrypte = cipher.update(iv, 'bin', 'base64')
  //     contenuCrypte += cipher.update(contenuString, 'utf8', 'base64')
  //     contenuCrypte += cipher.final('base64')
  //
  //     return {contenuCrypte, encryptedSecretKey, iv}
  //   })
  // }

  async decrypterAsymetrique(contenuSecret) {
    return dechiffrerCleSecreteForge(this.cleForge, contenuSecret)
    // // debug("CONTENU SECRET CHIFFRE : " + contenuSecret)
    // let cleSecrete = forge.util.decode64(contenuSecret);
    //
    // // Decrypter la cle secrete avec notre cle privee
    // var decryptedSecretKey = this.cleForge.decrypt(cleSecrete, 'RSA-OAEP', {
    //   md: forge.md.sha256.create(),
    //   mgf1: {
    //     md: forge.md.sha256.create()
    //   }
    // });
    // return decryptedSecretKey;
  }

  // _creerCipherKey(certificat) {
  //   let promise = new Promise((resolve, reject) => {
  //     this.genererKeyAndIV((err, {key, iv})=>{
  //       if(err) {
  //         reject(err);
  //       }
  //
  //       var cipher = crypto.createCipheriv(this.algorithm, key, iv);
  //
  //       // Encoder la cle secrete
  //       var encryptedSecretKey = this.crypterContenuAsymetric(certificat.publicKey, key);
  //       iv = iv.toString('base64');
  //
  //       resolve({cipher, encryptedSecretKey, iv});
  //
  //     });
  //   });
  //
  //   return promise;
  // }

  // crypterContenuAsymetric(publicKey, contentToEncrypt) {
  //   var keyByteString = forge.util.bytesToHex(contentToEncrypt);
  //   var encryptedContent = publicKey.encrypt(keyByteString, this.rsaAlgorithm, {
  //     md: forge.md.sha256.create(),
  //     mgf1: {
  //       md: forge.md.sha256.create()
  //     }
  //   });
  //
  //   encryptedContent = forge.util.encode64(encryptedContent);
  //   return encryptedContent;
  // }

  // async creerCipherChiffrageAsymmetrique(certificats) {
  //
  //   const keyIv = await new Promise((resolve, reject) => {
  //     this.genererKeyAndIV((err, keyIv)=>{
  //       if(err) return reject(err)
  //       resolve(keyIv)
  //     })
  //   })
  //
  //   const cipher = crypto.createCipheriv(this.algorithm, keyIv.key, keyIv.iv)
  //
  //   // Encoder la cle secrete
  //   const iv = keyIv.iv.toString('base64')
  //
  //   const certClesChiffrees = {}
  //   certificats.forEach(certs=>{
  //     const certPem = certs[0]
  //     const cert = this.chargerCertificatPEM(certPem)
  //     const fingerprint = getCertificateFingerprints(cert).fingerprintSha256B64
  //     var encryptedSecretKey = this.crypterContenuAsymetric(cert.publicKey, keyIv.key);
  //     certClesChiffrees[fingerprint] = encryptedSecretKey
  //   })
  //
  //   return({cipher, certClesChiffrees, iv})
  // }

  async dechiffrerContenuAsymetric(cleChiffree, iv, tag, contenuChiffre) {
    debug("dechiffrerContenuAsymetric: Cle secrete: %s\nIV: %s, Tag: %s\ncontenuChiffre: %O", cleSecrete, iv, tag, contenuChiffre)
    const cleSecreteDechiffree = await this.decrypterAsymetrique(cleChiffree)
    // debug("Cle secrete dechiffree : %O", cleSecreteDechiffree)

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

  // async creerCipherChiffrageAsymmetrique(certificats) {
  //
  //   const keyIv = await new Promise((resolve, reject) => {
  //     this.genererKeyAndIV((err, keyIv)=>{
  //       if(err) return reject(err)
  //       resolve(keyIv)
  //     })
  //   })
  //
  //   const cipher = crypto.createCipheriv(this.algorithm, keyIv.key, keyIv.iv)
  //
  //   // Encoder la cle secrete
  //   const iv = keyIv.iv.toString('base64')
  //
  //   const certClesChiffrees = {}
  //   certificats.forEach(certs=>{
  //     const certPem = certs[0]
  //     const cert = this.chargerCertificatPEM(certPem)
  //     const fingerprint = getCertificateFingerprints(cert).fingerprintSha256B64
  //     var encryptedSecretKey = this.crypterContenuAsymetric(cert.publicKey, keyIv.key);
  //     certClesChiffrees[fingerprint] = encryptedSecretKey
  //   })
  //
  //   return({cipher, certClesChiffrees, iv})
  // }

  async creerCipherChiffrageAsymmetrique(certificatsPem, domaine, identificateurs_document, opts) {
    const cipher = await creerCipher()

    const cipherWrapper = {
      update: cipher.update,
      finish: async () => {
        const infoChiffrage = await cipher.finish()
        const meta = infoChiffrage.meta

        console.debug("Info meta cipher : %O", meta)

        // Chiffrer le password avec les certificats
        const commandeMaitreCles = await preparerCommandeMaitrecles(
          certificatsPem,
          infoChiffrage.password, domaine, meta.hachage_bytes, meta.iv, meta.tag,
          identificateurs_document,
          opts
        )

        return {meta, commandeMaitreCles}
      }
    }

    return cipherWrapper
  }

  // genererKeyAndIV(cb) {
  //   var lenBuffer = 16 + 32;
  //   crypto.pseudoRandomBytes(lenBuffer, (err, pseudoRandomBytes) => {
  //     // Creer deux buffers, iv (16 bytes) et password (24 bytes)
  //     var iv = pseudoRandomBytes.slice(0, 16);
  //     var key = pseudoRandomBytes.slice(16, pseudoRandomBytes.length);
  //     cb(err, {key: key, iv: iv});
  //   });
  // }

  // async genererRandomBytes(nbBytes, opts) {
  //   if(!opts) opts = {}
  //   return new Promise((resolve, reject)=>{
  //     crypto.pseudoRandomBytes(nbBytes, (err, pseudoRandomBytes) => {
  //       // Creer deux buffers, iv (16 bytes) et password (24 bytes)
  //       if(err) reject(err)
  //       else {
  //         if(opts.base64) {
  //           // Encoder les bytes en base64
  //           const b64Content = pseudoRandomBytes.toString('base64')
  //           resolve(b64Content)
  //         } else {
  //           resolve(pseudoRandomBytes)
  //         }
  //       }
  //     });
  //   })
  // }

  // extraireClePubliqueFingerprint(certificat) {
  //
  //   const fingerprint = getCertificateFingerprint(certificat);
  //
  //   const clePubliquePEM = forge.pki.publicKeyToPem(certificat.publicKey);
  //
  //   var clePublique = clePubliquePEM
  //     .replace('-----BEGIN PUBLIC KEY-----', '')
  //     .replace('-----END PUBLIC KEY-----', '');
  //
  //   // Remplacer les \n pour mettre la cle sur une seule ligne
  //   clePublique = clePublique.split('\n').join('');
  //
  //   return {clePublique, fingerprint};
  // }

  // Sauvegarde un message de certificat en format JSON
  async sauvegarderMessageCertificat(message, fingerprintBase58) {
    if(typeof(message) === 'string') message = JSON.parse(message)
    const chaine_pem = message.chaine_pem || message.resultats.chaine_pem

    if(!fingerprintBase58) {
      // Calculer hachage du cerficat
      const cert = forge.pki.certificateFromPem(chaine_pem[0])
      fingerprintBase58 = await hacherCertificat(cert)
    }

    // DEPRECATED, remplace par redis
    // // Convertir fingerprint de b64 vers hex (b64 pas safe comme nom de fichier)
    // const fichier = path.join(REPERTOIRE_CERTS_TMP, fingerprintBase58 + '.pem')
    //
    // let fichierExiste = await new Promise((resolve, reject)=>{
    //   try {
    //     debug("Verification existance fichier certificat %s", fingerprintBase58)
    //
    //     // Verifier si le fichier existe deja
    //     fs.access(fichier, fs.constants.F_OK, (err) => {
    //       let existe = ! err;
    //       debug("Fichier existe? %s : %s", existe, fichier)
    //       resolve(existe);
    //     })
    //   } catch (err) {
    //     return reject(err)
    //   }
    // })
    // debug("sauvegarderMessageCertificat, fichier %s existe? %s", fingerprintBase58, fichierExiste)
    let fichierExiste = false
    const cleCert = 'certificat:' + fingerprintBase58,
          expiration = ''+(48 * 60 * 60)  // 48h en secondes

    debug("sauvegarderMessageCertificat")

    if(this.redisClient) {
      debug("Sauvegarder/touch certificat dans client redis : %s", fingerprintBase58)
      const resultat = await new Promise((resolve, reject)=>{
        this.redisClient.expire(cleCert, expiration, (err, res)=>{
          if(err) return reject(err)
          resolve(res)
        })
      })
      fichierExiste = resultat > 0
      debug("Certificat %s existe?%s", fingerprintBase58, fichierExiste)
    }

    if( ! fichierExiste ) {
      // let json_message = JSON.parse(message);
      // let chaine_pem = json_message.chaine_pem || json_message.resultats.chaine_pem

      // Verifier la chain de certificats
      const store = new forgecommon.CertificateStore(this.ca)
      if(store.verifierChaine(chaine_pem, {validityCheckDate: null})) {
        const chaineCerts = chaine_pem.map(pem=>{
          return forge.pki.certificateFromPem(pem)
        })
        let certificat = chaineCerts[0]
        let fingerprint = await hacherCertificat(certificat)

        // La chaine est valide, on sauvegarde le certificat
        const certCache = {ts: new Date().getTime(), chaineForge: chaineCerts}
        // debug("sauvegarderMessageCertificat: Ajouter certificat au cache : %O", certCache)
        this.cacheCertsParFingerprint[fingerprint] = certCache

        if(this.redisClient) {
          this.redisClient.set(cleCert, JSON.stringify(chaine_pem), 'NX', 'EX', expiration)
        }

        // DEPRECATED - remplace par redis
        // // Sauvegarder sur disque
        // await new Promise((resolve, reject)=>{
        //   try {
        //     fs.writeFile(fichier, chaine_pem.join('\n'), {'encoding': 'utf-8', flag: 'wx'}, err=>{
        //       if(err) {
        //         debug("sauvegarderMessageCertificat Erreur sauvegarde certificat:\n%O", err)
        //         if(err.code === 'EEXIST') return resolve()  // EEXIST
        //         return reject(err)
        //       }
        //       debug("Fichier certificat sauvegarde : %s", fichier);
        //       return resolve()
        //     })
        //   } catch(err) {
        //     return reject(err)
        //   }
        // })

        // Informatif seulement : verifier si c'est bien le certificat qui a ete demande
        if(fingerprint !== fingerprintBase58) {
          debug(`WARN: Certificat ${fingerprint} sauvegarde localement, mais ne correspond pas au fingerprint demande ${fingerprintBase58}`)
        }

        debug("sauvegarderMessageCertificat Cert %s sauvegarde", fingerprintBase58)

        return fingerprintBase58

      } else {
        throw new Error(`Erreur validation certificat recu : ${json_message.fingerprint}`)
      }

    } else {
      debug("Fichier certificat existe deja pour certificat (%s.pem)", fingerprintBase58)
      return fingerprintBase58
    }
  }

  // Charge la chaine de certificats pour ce fingerprint
  async getCertificate(fingerprint, opts) {
    opts = opts || {}
    const fingerprintEffectif = fingerprint  // Changement pour multibase, multihash

    // Tenter de charger le certificat a partir du cache memoire
    debug("getCertificate: Fingerprint (nowait: %s) : %s", opts.nowait, fingerprintEffectif)
    try {
      const cacheCert = this.cacheCertsParFingerprint[fingerprintEffectif]
      if(cacheCert && cacheCert.chaineForge) {
        cacheCert.ts = new Date().getTime()  // Touch
        return cacheCert.chaineForge
      }
    } catch(err) {
      debug("ERROR getCertificate Erreur verification certificat dans le cache %O", err)
    }

    // Verifier si le certificat existe sur le disque
    if(this.redisClient) {
      try {
        const chaine = await chargerCertificatFS(this.redisClient, fingerprintEffectif)

        // Valider le certificat avec le store
        let valide = true
        try {
          forge.pki.verifyCertificateChain(this.caStore, chaine)
          const certCache = {ts: new Date().getTime(), chaineForge: chaine}
          // debug("getCertificate: Ajouter certificat au cache : %O", certCache)
          this.cacheCertsParFingerprint[fingerprintEffectif] = certCache
          return chaine
        } catch (err) {
          valide = false
          debug('Certificate verification failure: %O', err)
          // const erreur = new Error("Certificat local invalide pour " + fingerprint)
          err.fingerprint = fingerprint
          throw err
        }

      } catch(err) {
        debug("Erreur chargement certificat sur disque, tenter via MQ : %O", err)
      }
    }

    // Demander le certificat via MQ
    let certificat = null
    if( ! opts.nowait && ! certificat && this.gestionnaireCertificatMessages ) {

      // Effectuer une requete pour recuperer le certificat
      certificat = await new Promise((resolve, reject)=>{
        const callback = (err, chaineForge) => {
          if(err) reject(err)
          else {
            resolve(chaineForge)
          }
        }
        this.gestionnaireCertificatMessages.demanderCertificat(fingerprint, {callback})
      })

    }

    if(!certificat) {
      const erreur = new CertificatInconnu(`Certificat inconnu : ${fingerprint}`)
      erreur.fingerprint = fingerprint
      throw erreur
    }

    return certificat
  }

  async maintenanceCache() {
    const cacheCertsParFingerprint = {}
    const expiration = new Date().getTime() - EXPIRATION_CERTCACHE
    for(let key in this.cacheCertsParFingerprint) {
      const value = this.cacheCertsParFingerprint[key]
      const ts = value.ts
      if(ts >= expiration) {
        // Conserver, pas expire
        cacheCertsParFingerprint[key] = value
      }
    }

    // Conserver nouvelle version du cache
    debug("Maintenance cache amqpdao.pki (%d keys left)", Object.keys(cacheCertsParFingerprint).length)
    this.cacheCertsParFingerprint = cacheCertsParFingerprint
  }

  // Verifie la signature d'un message
  // Retourne vrai si le message est valide, faux si invalide.
  // async verifierSignatureMessage(message) {
  //   let fingerprint = message['en-tete']['fingerprint_certificat'];
  //   let signatureBase64 = message['_signature'];
  //   let signature = Buffer.from(signatureBase64, 'base64');
  //
  //   let certificatChaine = null
  //   try {
  //     // Tenter de charger le certificat localement
  //     debug("Tenter de charger le certificat localement : " + fingerprint)
  //     certificatChaine = await this.getCertificate(fingerprint)
  //     debug("Certifcat charge")
  //   } catch (err) {
  //     debug("warning - Erreur chargement chaine localement, verifier d'autres methodes de chargement\n%O", err)
  //   }
  //
  //   if( ! certificatChaine && message['_certificat']) {
  //     // Verifier la chaine de certificats inclue avec le message
  //     const chaineInclue = message['_certificat']
  //     const store = new forgecommon.CertificateStore(this.ca)
  //     if(store.verifierChaine(chaineInclue)) {
  //       certificatChaine = [this.chargerCertificatPEM(chaineInclue[0])]
  //     }
  //   }
  //
  //   if( ! certificatChaine ) {
  //     debug("Certificat inconnu : " + fingerprint)
  //     throw new CertificatInconnu("Certificat inconnu : " + fingerprint)
  //   }
  //   const certificat = certificatChaine[0]
  //
  //   let messageFiltre = {};
  //   for(let cle in message) {
  //     if( ! cle.startsWith('_') ) {
  //       messageFiltre[cle] = message[cle];
  //     }
  //   }
  //   // Stringify en ordre (stable)
  //   messageFiltre = stringify(messageFiltre);
  //
  //   let keyLength = certificat.publicKey.n.bitLength();
  //   // Calcul taille salt:
  //   // http://bouncy-castle.1462172.n4.nabble.com/Is-Bouncy-Castle-SHA256withRSA-PSS-compatible-with-OpenSSL-RSA-PSS-padding-with-SHA256-digest-td4656843.html
  //   // Changement a 64 pour supporter iPhone
  //   let saltLength = 64  // (keyLength - 512) / 8 - 2;
  //
  //   var pss = forge.pss.create({
  //     md: forge.md.sha512.create(),
  //     mgf: forge.mgf.mgf1.create(forge.md.sha512.create()),
  //     saltLength,
  //     // optionally pass 'prng' with a custom PRNG implementation
  //   });
  //   var md = forge.md.sha512.create();
  //   md.update(messageFiltre, 'utf8');
  //
  //   try {
  //     var publicKey = certificat.publicKey
  //     let valide = publicKey.verify(md.digest().getBytes(), signature, pss)
  //     return valide
  //   } catch (err) {
  //     debug("Erreur verification signature")
  //     debug(err)
  //     return false
  //   }
  //
  // }

  // Calcule le IDMG a partir d'un certificat PEM
  // calculerIdmg(certificatPEM) {
  //   const cert = forge.pki.certificateFromPem(certificatPEM)
  //
  //   const fingerprint = forge.md.sha512.sha224.create()
  //     .update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())
  //     .digest()
  //     .toHex()
  //   const buffer = Buffer.from(fingerprint, 'hex')
  //   const idmg = base58.encode(buffer)
  //
  //   return idmg
  // }

  // signerContenuString(contenuString) {
  //   return forgecommon.signerContenuString(this.cleForge, contenuString)
  // }

  // getChainePems() {
  //   const pems = this.chainePEM
  //   return splitPEMCerts(pems)
  // }

}

// function getCertificateFingerprint(cert) {
//   const fingerprint = forge.md.sha1.create()
//     .update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())
//     .digest()
//     .toHex();
//   return fingerprint
// }

// function getCertificateFingerprintB64(cert) {
//   const digest = forge.md.sha1.create()
//     .update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())
//     .digest()
//
//   const fingerprintBase64 = forge.util.encode64(digest.getBytes())
//   return fingerprintBase64
// }

// function getCertificateFingerprints(cert) {
//   const digestSha256Bytes = forge.md.sha256.create()
//     .update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())
//     .digest()
//     .getBytes()
//   const fingerprint = getCertificateFingerprint(cert)
//   const fingerprintSha256 = forge.util.bytesToHex(digestSha256Bytes)
//   const fingerprintSha256B64 = forge.util.encode64(digestSha256Bytes)
//
//   return {fingerprint, fingerprintSha256, fingerprintSha256B64}
// }

// function splitPEMCerts(certs) {
//   var splitCerts = certs.split(PEM_CERT_DEBUT).map(c=>{
//     return PEM_CERT_DEBUT + c
//   })
//   return splitCerts.slice(1)
// }

async function chargerCertificatFS(redisClient, fingerprint) {
  const cleCert = 'certificat:' + fingerprint
  return new Promise((resolve, reject) => {
    redisClient.get(cleCert, async (err, data)=>{
      if(err) return reject(err)
      debug("Resultat chargement cert FS : %O", data)

      if(!data) return reject(new Error("Aucune donnee pour certificat " + fingerprint)) // No data

      try {
        const listePems = JSON.parse(data)   //splitPEMCerts(data)
        const chaineForge = listePems.map(pem=>{
          return forge.pki.certificateFromPem(pem)
        })

        const fingerprintCalcule = await hacherCertificat(listePems[0])
        var fingerprintMatch = false
        if(fingerprintCalcule === fingerprint) {
          fingerprintMatch = true
        }
        if( ! fingerprintMatch ) {
          // Supprimer certificat invalide
          redisClient.del(cleCert)
          return reject('Fingerprint ' + fingerprintCalcule + ' ne correspond pas au fichier : ' + fingerprint + '.pem. Fichier supprime.');
        }

        resolve(chaineForge)
      } catch(err) {
        return reject(err)
      }
    })
  })
  // Deprecated, remplace par redis
  // const chaineForge = await new Promise((resolve, reject)=>{
  //   let fichier = path.join(REPERTOIRE_CERTS_TMP, fingerprint + '.pem')
  //   fs.readFile(fichier, 'utf8', (err, data)=>{
  //     if(err) return reject(err)
  //     if(!data) return reject(new Error("Aucune donnee pour certificat " + fingerprint)) // No data
  //
  //     try {
  //       const listePems = splitPEMCerts(data)
  //       const chaineForge = listePems.map(pem=>{
  //         return forge.pki.certificateFromPem(pem)
  //       })
  //
  //       const fingerprintCalcule = getCertificateFingerprint(chaine[0])
  //       var fingerprintMatch = false
  //       if(format === fingerprintCalcule === fingerprint) {
  //         fingerprintMatch = true
  //       }
  //       if( ! fingerprintMatch ) {
  //         // Supprimer fichier invalide
  //         // fs.unlink(fichier, ()=>{});
  //         return reject('Fingerprint ' + fingerprintCalcule + ' ne correspond pas au fichier : ' + fingerprint + '.pem. Fichier supprime.');
  //       }
  //
  //       return chaineForge
  //
  //     } catch(err) {
  //       return reject(err)
  //     }
  //   })
  // })
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
