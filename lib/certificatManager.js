const debug = require('debug')('millegrilles:common:certificatmanager')
const forge = require('node-forge')

// const MG_EXCHANGE_PROTEGE = '3.protege'
// const ROUTING_CERTIFICAT = 'requete.certificat'
const MG_ROUTING_EMETTRE_CERTIFICAT = 'evenement.Pki.infoCertificat'
// const TYPES_MESSAGES_ROOM_ACCEPTES = ['evenement', 'transaction', 'commande']
// const routingKeyNouvelleTransaction = 'transaction.nouvelle'


class GestionnaireCertificatMessages {

  constructor(pki, mq) {
    this.pki = pki
    this.mq = mq

    // Conserver une liste de certificats connus, permet d'eviter la
    // sauvegarder redondante du meme certificat
    this.certificatsConnus = {}
  }

  sauvegarderMessageCertificat(messageContent, json_message) {
    this.pki.sauvegarderMessageCertificat(messageContent, json_message.fingerprint)
  }

  async verifierSignatureMessage(messageDict) {
    // Valider le contenu du message - hachage et signature
    let hashTransactionCalcule = this.pki.hacherTransaction(messageDict)
    const entete = messageDict['en-tete']
    if(entete) {
      let hashTransactionRecu = entete['hachage-contenu']
      if(hashTransactionCalcule !== hashTransactionRecu) {
        debug("Erreur hachage incorrect : %s, message dropped: %s", hashTransactionCalcule, entete['uuid-transaction'])
        return false
      }
    } else {
      debug("Reponse sans entete -- on verifie la signature");
    }

    const signatureValide = await this.pki.verifierSignatureMessage(messageDict)

    return signatureValide
  }

  demanderCertificat(fingerprint) {
    var requete = {fingerprint}
    var routingKey = 'certificat.' + fingerprint

    // Transmettre requete - elle va etre interceptee par un autre processus
    this.mq.transmettreRequete(routingKey, requete, {nowait: true})
    
  }

  demanderCertificatMaitreDesCles() {
    const tempsCourant = new Date().getTime();
    if(this.certificatMaitreDesCles && this.certificatMaitreDesCles.expiration < tempsCourant) {
      return new Promise((resolve, reject) => {
        resolve(this.certificatMaitreDesCles.cert);
      });
    } else {
      let objet_crypto = this;
      // console.debug("Demander certificat MaitreDesCles");
      var requete = {}
      var routingKey = 'MaitreDesCles.certMaitreDesCles';
      return this.mq.transmettreRequete(routingKey, requete)
      .then(reponse=>{
        let messageContent = decodeURIComponent(escape(reponse.content));
        let json_message = JSON.parse(messageContent);
        // console.debug("Reponse cert maitre des cles");
        // console.debug(messageContent);
        const cert = forge.pki.certificateFromPem(json_message.certificat);
        objet_crypto.certificatMaitreDesCles = {
          expiration: tempsCourant + 120000,
          cert,
        }

        return cert;
      })
    }
  }

  transmettreCertificat(properties) {
    debug("Repondre avec le certificat local")
    let messageCertificat = this.pki.preparerMessageCertificat()
    let fingerprint = messageCertificat.fingerprint

    if(properties && properties.correlationId && properties.replyTo) {
      // On repond avec le certificat
      this.mq.transmettreReponse(messageCertificat, properties.replyTo, properties.correlationId)
    } else {
      // Il n'y a pas de demandeur specifique, on emet le certificat
      let messageJSONStr = JSON.stringify(messageCertificat)
      this.mq._publish(MG_ROUTING_EMETTRE_CERTIFICAT, messageJSONStr)
    }

    return fingerprint
  }
}

module.exports = GestionnaireCertificatMessages
