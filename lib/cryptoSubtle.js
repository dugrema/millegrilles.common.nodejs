const crypto = require('crypto');

function str2ab(str) {

  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return bufView;

}

function ab2hex(buffer) {
  var s = '', h = '0123456789abcdef';
  (new Uint8Array(buffer)).forEach((v) => { s += h[v >> 4] + h[v & 15]; });
  return s;
}

// function toHexString(byteArray) {
//   return Array.prototype.map.call(byteArray, function(byte) {
//     return ('0' + (byte & 0xFF).toString(16)).slice(-2);
//   }).join('');
// }

function toByteArray(hexString) {
  var result = [];
  for (var i = 0; i < hexString.length; i += 2) {
    result.push(parseInt(hexString.substr(i, 2), 16));
  }
  return result;
}

export function bufferToBase64(arrayBuffer) {
  var base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
  return base64String;
}

export class CryptageAsymetrique {

  constructor() {
    this.algorithm = "RSA-OAEP"
    this.hashFunction = "SHA-256"
  }

  async genererKeysNavigateur(opts) {
    if(!opts) opts = {}

    if(window && window.crypto && window.crypto.subtle) {
      console.log("SubtleCrypto est disponible, on l'utilise pour generer les cles");

      const keypair = await window.crypto.subtle.generateKey(
        {
          name: this.algorithm,
          modulusLength: opts.modulusLength || 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: opts.hashFunction || this.hashFunction
        },
        true,
        ['encrypt', 'decrypt']
      )

      console.debug(keypair)

      // Exporter cles privees et re-importer dans versions pour signer, decrypter
      const clePriveePkcs8AB = await window.crypto.subtle.exportKey("pkcs8", keypair.privateKey)
      const clePubliqueSpkiAB = await window.crypto.subtle.exportKey('spki', keypair.publicKey)

      try {
        const clePriveeDecrypt = await window.crypto.subtle.importKey(
          "pkcs8", clePriveePkcs8AB, {name: this.algorithm, hash: this.hashFunction}, false, ['decrypt']
        )
        console.debug("Cle dechiffrage : %O", clePriveeDecrypt)

        const keySizeInBits = 2048, digestSizeInBytes = 512 / 8
        const saltLength = Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2
        const clePriveeSigner = await window.crypto.subtle.importKey(
          'pkcs8', clePriveePkcs8AB, {name: 'RSA-PSS', hash: 'SHA-512'}, false, ['sign']
        )
        console.debug("Cle signature : %O", clePriveeSigner)

        return {
          clePublique: keypair.publicKey,
          clePubliqueSpki: btoa(String.fromCharCode.apply(null, new Uint8Array(clePubliqueSpkiAB))),
          clePriveePkcs8: btoa(String.fromCharCode.apply(null, new Uint8Array(clePriveePkcs8AB))),
          clePriveeDecrypt,
          clePriveeSigner,
        }
      } catch(err) {
        console.error("Erreur : %O", err)
        return
      }

    }
  }

  async preparerClePrivee(clePriveePem) {

    // var clePriveePemContent = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDD0tPV/du2vftjvXj1t/gXTK39sNBVrOAEb/jKzXae+Xa0H+3LhZaQIQNMfACiBSgIfZUvEGb+7TqXWQpoLoFR/R7MvGWcSk98JyrVtveD8ZmZYyItSY7m2hcasqAFiKyOouV5vzyRe87/lEyzzBpF3bQQ4IDaQu+K9Hj5fKuU6rrOeOhsdnJc+VdDQLScHxvMoLZ9Vtt+oK9J4/tOLwr4CG8khDlBURcBY6gPcLo3dPU09SW+6ctX2cX4mkXx6O/0mmdTmacr/vu50KdRMleFeZYOWPAEhhMfywybTuzBiPVIZVP8WFCSKNMbfi1S9A9PdBqnebwwHhX3/hsEBt2BAgMBAAECggEABEI1P6nf6Zs7mJlyBDv+Pfl5rjL2cOqLy6TovvZVblMkCPpJyFuNIPDK2tK2i897ZaXfhPDBIKmllM2Hq6jZQKB110OAnTPDg0JxzMiIHPs32S1d/KilHjGff4Hjd4NXp1l1Dp8BUPOllorR2TYm2x6dcCGFw9lhTr8O03Qp4hjn84VjGIWADYCk83mgS4nRsnHkdiqYnWx1AjKlY51yEK6RcrDMi0Th2RXrrINoC35sVv+APt2rkoMGi52RwTEseA1KZGFrxjq61ReJif6p2VXEcvHeX6CWLx014LGk43z6Q28P6HgeEVEfIjyqCUea5Du/mYb/QsRSCosXLxBqwQKBgQD1+fdC9ZiMrVI+km7Nx2CKBn8rJrDmUh5SbXn2MYJdrUd8bYNnZkCgKMgxVXsvJrbmVOrby2txOiqudZkk5mD3E5O/QZWPWQLgRu8ueYNpobAX9NRgNfZ7rZD+81vh5MfZiXfuZOuzv29iZhU0oqyZ9y75eHkLdrerNkwYOe5aUQKBgQDLzapDi1NxkBgsj9iiO4KUa7jvD4JjRqFy4Zhj/jbQvlvM0F/uFp7sxVcHGx4r11C+6iCbhX4u+Zuu0HGjT4d+hNXmgGyxR8fIUVxOlOtDkVJa5sOBZK73/9/MBeKusdmJPRhalZQfMUJRWIoEVDMhfg3tW/rBj5RYAtP2dTVUMQKBgDs8yr52dRmT+BWXoFWwaWB0NhYHSFz/c8v4D4Ip5DJ5M5kUqquxJWksySGQa40sbqnD05fBQovPLU48hfgr/zghn9hUjBcsoZOvoZR4sRw0UztBvA+7jzOz1hKAOyWIulR6Vca0yUrNlJ6G5R56+sRNkiOETupi2dLCzcqb0PoxAoGAZyNHvTLvIZN4iGSrjz5qkM4LIwBIThFadxbv1fq6pt0O/BGf2o+cEdq0diYlGK64cEVwBwSBnSg4vzlBqRIAUejLjwEDAJyA4EE8Y5A9l04dzV7nJb5cRak6CrgXxay/mBJRFtaHxVlaZGxYPGSYE6UFS0+3EOmmevvDZQBf4qECgYEA0ZF6Vavz28+8wLO6SP3w8NmpHk7K9tGEvUfQ30SgDx4G7qPIgfPrbB4OP/E0qCfsIImi3sCPpjvUMQdVVZyPOIMuB+rV3ZOxkrzxEUOrpOpR48FZbL7RN90yRQsAsrp9e4iv8QwB3VxLe7X0TDqqnRyqrc/osGzuS2ZcHOKmCU8='

    console.debug("Cle Privee PEM:\n%s", clePriveePem)

    // Enlever premiere et dernirer ligne pour passer de PEM a Pkcs8
    var clePemSplit = clePriveePem.replace(/\r/g, '').split('\n')
    clePemSplit = clePemSplit.slice(1, clePemSplit.length-2)
    const clePriveePemContent = clePemSplit.join('')
    console.debug("Cle Privee PEM content stripped:\n%s", clePriveePemContent)
    const clePriveePEMbinstr = window.atob(clePriveePemContent)
    const clePriveeAB = str2ab(clePriveePEMbinstr)
    console.debug("Cle privee ArrayBuffer:\n%s", clePriveeAB)

    try {
      const clePriveeDecrypt = await window.crypto.subtle.importKey(
        "pkcs8", clePriveeAB, {name: this.algorithm, hash: this.hashFunction}, false, ['decrypt']
      )
      console.debug("Cle dechiffrage \n%O", clePriveeDecrypt)

      const keySizeInBits = 2048, digestSizeInBytes = 512 / 8
      const saltLength = Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2
      const clePriveeSigner = await window.crypto.subtle.importKey(
        'pkcs8', clePriveeAB, {name: 'RSA-PSS', hash: 'SHA-512'}, false, ['sign']
      )
      console.debug("Cle signature \n%O", clePriveeSigner)

      return {
        clePriveeDecrypt,
        clePriveeSigner,
      }
    } catch(err) {
      console.error("Erreur preparation cles privees subtle\n%O", err)
      return {err}
    }
  }

  // Generer un nouveau keypair
  // opts = {
  //   modulusLength: taille de la cle (defaut : 2048)
  //   hashFunction: fonction de hachage (default : this.hashFunction -> SHA-256)
  // }
  genererKeyPair(opts) {
    if(!opts) opts = {}

    return new Promise((resolve, reject)=>{

      if(window && window.crypto && window.crypto.subtle) {
        // console.log("SubtleCrypto est disponible, on l'utilise pour generer les cles");

        window.crypto.subtle.generateKey(
          {
            name: this.algorithm,
            modulusLength: opts.modulusLength || 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: opts.hashFunction || this.hashFunction
          },
          true,
          ["encrypt", "decrypt"]
        )
        .then(keyPair=>{
          // console.debug("Cles generees");
          // console.debug(keyPair);

          // Exporter en format PEM
          window.crypto.subtle.exportKey('spki', keyPair.publicKey)
          .then(clePublique=>{
            // console.debug(clePublique);
            window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
            .then(clePrivee=>{
              // console.warn(clePrivee);

              let cles = {
                clePrivee: btoa(String.fromCharCode.apply(null, new Uint8Array(clePrivee))),
                clePublique: btoa(String.fromCharCode.apply(null, new Uint8Array(clePublique))),
              };

              // console.warn(cles);

              resolve(cles);
            })
          })
        })

      } else {
        throw(Object({erreur: "Pas de Subtle Crypto"}));
      }

    });
  }

  // Crypte une cle secrete. Passer la clePublique en format base64 (i.e. PEM
  // sur une ligne sans wrappers) et la cleSecreteHexString en format
  // hex (e.g. 64 chars cd0adcc5c75...)
  crypterCleSecrete(clePublique, cleSecreteHexString) {
    // var keyByteString = forge.util.bytesToHex(cleSecrete);

    // console.log("Crypter cle secrete. Cle publique : ");
    // console.log(clePublique);
    let clePubliqueBuffer = str2ab(window.atob(clePublique));
    // console.log(clePubliqueBuffer);

    // console.warn("Cle secrete");
    // console.warn(cleSecrete);
    // let cleSecreteHex = cleSecrete.toString('hex');
    // console.warn(cleSecreteHexString);
    let cleSecreteBuffer = str2ab(cleSecreteHexString);
    // console.warn(cleSecreteBuffer);

    return window.crypto.subtle.importKey(
      'spki',
      clePubliqueBuffer,
      {
        name: this.algorithm,
        hash: this.hashFunction,
      },
      true,
      ["encrypt"]
    )
    .then(clePubliqueImportee=>{

      // console.debug("Cle publique chargee");
      // console.debug(clePubliqueImportee);

      return window.crypto.subtle.encrypt(
        {
          name: this.algorithm
        },
        clePubliqueImportee,
        cleSecreteBuffer
      );

    });

  }

  decrypterCleSecrete(cleSecreteCryptee, clePrivee) {
    // console.debug("Decrypter cle secrete");
    // console.debug("Cle privee")
    // console.warn(clePrivee);
    let clePriveeBuffer = str2ab(window.atob(clePrivee));
    // console.log(clePriveeBuffer);
    // console.log("Cle secrete cryptee");
    // console.log(cleSecreteCryptee);

    return window.crypto.subtle.importKey(
      'pkcs8',
      clePriveeBuffer,
      {
        name: this.algorithm,
        hash: this.hashFunction,
      },
      true,
      ["decrypt"]
    )
    .then(clePriveeImportee=>{

      // console.log("Cle privee chargee");
      // console.log(clePriveeImportee);

      let cleSecreteCrypteeBuffer = str2ab(window.atob(cleSecreteCryptee));

      return window.crypto.subtle.decrypt(
        {
          name: this.algorithm
        },
        clePriveeImportee,
        cleSecreteCrypteeBuffer
      );

    })
    .then(cleSecreteDecryptee=>{
      // console.log("Cle secrete decryptee");
      // console.log(cleSecreteDecryptee);
      let cleSecreteB64 = btoa(String.fromCharCode.apply(null, new Uint8Array(cleSecreteDecryptee)));
      // console.log(cleSecreteB64);
      return cleSecreteB64;
    });

  }

  async signerContenuString(clePrivee, contenuString) {

    const paramsSignature = {
      name: 'RSA-PSS',
      saltLength: 20,
    }

    const contenuAb = str2ab(contenuString)

    const signature = await window.crypto.subtle.sign(paramsSignature, clePrivee, contenuAb)
    const signatureBase64 = btoa(String.fromCharCode.apply(null, new Uint8Array(signature)));

    return signatureBase64

    // // Creer algo signature et signer
    // const signMd = md.sha512.create()
    // signMd.update(contenuString, 'utf-8')
    //
    // var pssInstance = pss.create({
    //   md: md.sha512.create(),
    //   mgf: mgf.mgf1.create(md.sha512.create()),
    //   saltLength: 20
    // });
    //
    // const signature = util.encode64( clePrivee.sign(signMd, pssInstance) )
    //
    // return signature;
  }
}

export function genererAleatoireBase64(nbBytes) {
  const aleatAB = new ArrayBuffer(nbBytes);
  let abView = new Uint8Array(aleatAB);
  window.crypto.getRandomValues(abView);
  let aleatB64 = btoa(String.fromCharCode.apply(null, abView));
  return aleatB64
}

export class CryptageSymetrique {

  genererCleSecreteIv() {
    var cleSecreteLocal = null;
    var cleSecreteExporteeLocal = null;

    return window.crypto.subtle.generateKey(
      {
        name: 'AES-CBC',
        length: 256,
      },
      true,
      ['encrypt', 'decrypt']
    ).then(cleSecrete=>{
      // console.debug("Cle secrete generee");
      cleSecreteLocal = cleSecrete;

      // Exporter et crypter cle secrete
      return window.crypto.subtle.exportKey('raw', cleSecrete);
    })
    .then(cleSecreteExportee=>{
      // console.debug("Cle secrete exportee");
      cleSecreteExporteeLocal = cleSecreteExportee;

      const iv = new ArrayBuffer(16);
      let ivView = new Uint8Array(iv);
      window.crypto.getRandomValues(ivView);

      return({
        cleSecrete: cleSecreteLocal,
        cleSecreteExportee: cleSecreteExporteeLocal,
        iv
      });
    });
  }

  crypterContenu(buffer) {
    var clesIvLocal = null;

    return this.genererCleSecreteIv()
    .then(clesIv=>{
      clesIvLocal = clesIv;
      // console.log(clesIv.cleSecrete);
      // console.log('Cle secrete : ' + btoa(String.fromCharCode.apply(null, new Uint8Array(clesIv.cleSecreteExportee))));
      clesIvLocal.ivString =  btoa(String.fromCharCode.apply(null, new Uint8Array(clesIv.iv)));
      // console.debug('iv : ' + clesIvLocal.ivString);

      return window.crypto.subtle.encrypt(
        {
          name: "AES-CBC",
          iv: clesIv.iv
        },
        clesIv.cleSecrete,
        buffer
      )
    })
    .then(bufferCrypte=>{
      // console.debug("Fichier crypte dans buffer");
      return ({...clesIvLocal, bufferCrypte});
    });
  }

  chargerCleSecrete(cleBase64, ivBase64) {
    let cle = atob(cleBase64);
    let iv = atob(ivBase64);
    // console.log(cle);
    // console.log(iv);

    let ivABView = new Uint8Array(iv.length);
    for(let i=0; i<iv.length; i++) {
      ivABView[i] = iv.charCodeAt(i);
    }
    // console.debug("IV: ")
    // console.debug(ivABView);

    // console.warn("Cle hex : " + cle);
    let cleArray = toByteArray(cle);
    // console.warn(cleArray);

    let cleABView = new Uint8Array(cleArray.length);
    for(let i=0; i<cleArray.length; i++) {
      //cleABView[i] = cleArray.charCodeAt(i);
      cleABView[i] = cleArray[i];
    }
    // console.debug("Cle ABView ");
    // console.warn(cleABView);

    // Importer cle secrete format subtle
    return window.crypto.subtle.importKey(
      'raw',
      cleABView,
      {
        name: 'AES-CBC',
        length: 256,
      },
      false,
      ['decrypt']
    )
    .then(cleSecreteSubtle=>{
      // console.log("Cle subtle");
      // console.log(cleSecreteSubtle);

      return {cleSecrete: cleSecreteSubtle, iv: ivABView};
    })

  }

  decrypterContenu(buffer, cleSecrete, iv) {

    return window.crypto.subtle.decrypt(
      {name: "AES-CBC", iv: iv},
      cleSecrete,
      buffer
    );

  }

}

const cryptageAsymetrique = new CryptageAsymetrique();
const cryptageSymetrique = new CryptageSymetrique();

const PADDING_STR = '0123456789012345';  // Remplace par IV

export class MilleGrillesCryptoHelper {

  constructor() {
    this.algorithm = 'aes-256-cbc'  // Meme algorithme utilise sur MG en Python
    this.rsaAlgorithm = 'RSA-OAEP'
  }

  crypter(dictACrypter, clePublique) {

    var resultat = {};
    return new Promise((resolve, reject)=>{
      let contenuACrypter = str2ab(PADDING_STR + JSON.stringify(dictACrypter));
      // console.debug("Contenu a crypter");
      // console.debug(dictACrypter);
      // console.debug(contenuACrypter);

      cryptageSymetrique.crypterContenu(contenuACrypter)
      .then(result=>{
        // console.debug("Contenu crypte charge dans buffer");
        resultat.iv = result.ivString;
        // console.debug("IV");
        // console.debug(resultat.iv);
        resultat.bufferCrypte = result.bufferCrypte;
        // console.debug("Buffer crypte");
        // console.debug(resultat.bufferCrypte);

        // Preparer format cle secrete
        let cleSecrete = result.cleSecreteExportee;
        let cleSecreteHexString = ab2hex(cleSecrete);

        // console.warn("Cle secrete hex string");
        // console.warn(cleSecreteHexString);

        return cryptageAsymetrique.crypterCleSecrete(clePublique, cleSecreteHexString);
      })
      .then(cleSecreteCryptee=>{
        // console.debug("Cle secrete est cryptee");
        // console.debug(cleSecreteCryptee);

        resultat.cleSecreteCryptee = btoa(String.fromCharCode.apply(null, new Uint8Array(cleSecreteCryptee)));
        resolve(resultat);
      })
      .catch(err=>{
        console.error("Erreur dans crypterFichier");
        reject(err);
      })

      // this.creerCipherKey()
      // .then(cipher_key_iv=>{
      //
      //   let {cipher, key, iv} = cipher_key_iv;
      //   let keyString = key.toString('base64');
      //   let ivString = iv.toString('base64');
      //   // console.debug("Secrets key=" + keyString + ", iv=" + ivString);
      //
      //   let contenuCrypte = cipher.update(contenuACrypter, 'utf8', 'base64');
      //   contenuCrypte += cipher.final('base64');
      //   console.debug("Contenu crypte: " + contenuCrypte);
      //
      //   let resultat = {contenu: contenuACrypter, contenuCrypte, cleSecrete: keyString, iv: ivString};
      //   if(clePublique) {
      //     console.debug("Crypte cle secrete avec cle publique du maitredescles");
      //     cryptageAsymetrique.crypterCleSecrete(clePublique, key)
      //     .then(cleSecreteCryptee=>{
      //         resultat.cleSecreteCryptee = btoa(String.fromCharCode.apply(null, new Uint8Array(cleSecreteCryptee)));
      //         resolve(resultat);
      //     })
      //     .catch(err=>{
      //       console.error("Erreur cryptage cle secrete");
      //       reject(err);
      //     })
      //   } else {
      //     console.debug("La cle secrete ne sera pas cryptee");
      //     resolve(resultat);
      //   }
      //
      // })
      // .catch(err=>{
      //   console.error("Erreur creation cipher crypte");
      //   reject(err);
      // });
    })
  }

  crypterFichier(clePublique, acceptedFile) {

    return new Promise((resolve, reject) => {
      console.debug("Crypter fichier avec clePublique");

      var reader = new FileReader();
      var resultat = {};
      reader.onload = function() {
        var buffer = reader.result;
        console.debug("Ficher charge dans buffer, taille " + buffer.byteLength);

        // Crypter le fichier. Genere la cle secrete et le iv
        cryptageSymetrique.crypterContenu(buffer)
        .then(result=>{
          console.debug("Contenu crypte charge dans buffer");

          resultat.iv = result.ivString;
          console.debug("IV");
          console.debug(resultat.iv);
          resultat.bufferCrypte = result.bufferCrypte;

          // Preparer format cle secrete
          let cleSecrete = result.cleSecreteExportee;
          let cleSecreteHexString = ab2hex(cleSecrete);

          // console.warn("Cle secrete hex string");
          // console.warn(cleSecreteHexString);

          return cryptageAsymetrique.crypterCleSecrete(clePublique, cleSecreteHexString);
        })
        .then(cleSecreteCryptee=>{
          console.debug("Cle secrete est cryptee");
          console.debug(cleSecreteCryptee);

          resultat.cleSecreteCryptee = btoa(String.fromCharCode.apply(null, new Uint8Array(cleSecreteCryptee)));
          resolve(resultat);
        })
        .catch(err=>{
          console.error("Erreur dans crypterFichier");
          reject(err);
        })
      };

      reader.readAsArrayBuffer(acceptedFile);
    });

  }

  // Genere un cipher et crypter la cle secrete
  creerCipherCrypterCleSecrete(clePublique) {
    return new Promise((resolve, reject)=>{
      this.creerCipherKey()
      .then(cipher_key_iv=>{
        let {cipher, key, iv} = cipher_key_iv;
        let keyHexString = key.toString('hex');
        let ivString = iv.toString('base64');
        // console.warn("Secrets key=" + keyHexString + ", iv=" + ivString);
        // console.warn(key);

        // Crypter cle secrete avec la clePublique
        if(clePublique) {
          // console.debug("Crypte cle secrete avec cle publique du maitredescles");

          cryptageAsymetrique.crypterCleSecrete(clePublique, keyHexString)
          .then(cleSecreteCryptee=>{
            let resultat = {cipher, iv: ivString};
            resultat.cleSecreteCryptee = btoa(String.fromCharCode.apply(null, new Uint8Array(cleSecreteCryptee)));
            resolve(resultat);
          })
          .catch(err=>{
            console.error("Erreur cryptage cle secrete");
            reject(err);
          })
        } else {
          console.debug("La cle secrete ne sera pas cryptee");
          let resultat = {cipher, cleSecrete: keyHexString, iv: ivString};
          resolve(resultat);
        }

      })
      .catch(err=>{
        reject(err);
      });
    })
  }

  async crypterCleSecrete(cleSecrete, clePublique) {
    return await new Promise((resolve, reject) => {
      cryptageAsymetrique.crypterCleSecrete(clePublique, cleSecrete)
      .then(cleSecreteCryptee=>{
        cleSecreteCryptee = btoa(String.fromCharCode.apply(null, new Uint8Array(cleSecreteCryptee)));
        resolve({cleSecreteCryptee});
      })
      .catch(err=>{
        console.error("Erreur cryptage cle secrete");
        reject(err);
      })
    });
  }

  genererSecret(callback) {
    var lenBuffer = 16 + 32;
    crypto.pseudoRandomBytes(lenBuffer, (err, pseudoRandomBytes) => {
      if(err) {
        callback(err, {});
        return;
      }

      // Creer deux buffers, iv (16 bytes) et password (24 bytes)
      var iv = pseudoRandomBytes.slice(0, 16);
      var key = pseudoRandomBytes.slice(16, pseudoRandomBytes.length);
      callback(null, {key, iv});

    });
  }

  creerCipherKey() {
    let promise = new Promise((resolve, reject) => {
      this.genererSecret((err, {key, iv})=>{
        if(err) {
          reject(err);
        }

        // console.log("Creer cipher");
        var cipher = crypto.createCipheriv(this.algorithm, key, iv);

        resolve({cipher, key, iv});
      });
    });

    return promise;
  }

  decrypter(contenuCrypte, cleSecrete, iv) {
    return new Promise((resolve, reject)=>{

      let cleSecreteBuffer = str2ab(window.atob(cleSecrete));
      let ivBuffer = str2ab(window.atob(iv));

      // console.log("Creer decipher secretKey: " + cleSecreteBuffer.toString('base64') + ", iv: " + ivBuffer.toString('base64'));
      var decipher = crypto.createDecipheriv(this.algorithm, cleSecreteBuffer, ivBuffer);

      // console.debug("Decrypter " + contenuCrypte.toString('base64'));
      let contenuDecrypteString = decipher.update(contenuCrypte, 'base64',  'utf8');
      contenuDecrypteString += decipher.final('utf8');

      // console.debug("Contenu decrypte :");
      // console.debug(contenuDecrypteString);

      // let dictDecrypte = JSON.parse(contenuDecrypteString);
      // console.log("Dict decrypte: ");
      // console.log(dictDecrypte);

      resolve(contenuDecrypteString);
    });
  }

  decrypterSubtle(contenuCrypte, cleSecreteCryptee, iv, clePrivee) {

    return cryptageAsymetrique.decrypterCleSecrete(cleSecreteCryptee, clePrivee)
    .then(cleBase64=>{
      // console.debug("Cle secrete decryptee");
      // console.warn('Cle secrete b64 ' + cleBase64);

      return cryptageSymetrique.chargerCleSecrete(cleBase64, iv)
      .then(resultatCle=>{

        // console.debug("Cle secrete chargee");
        // console.warn(resultatCle);

        let ivABView = resultatCle.iv;
        let cleSecreteSubtle = resultatCle.cleSecrete;

        return cryptageSymetrique.decrypterContenu(contenuCrypte, cleSecreteSubtle, ivABView);

      })
    });

  }

}
