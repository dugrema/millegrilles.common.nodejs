import {expose as comlinkExpose} from 'comlink'
import { pki as forgePki } from 'node-forge'
import { CertificateStore } from '@dugrema/millegrilles.common/lib/forgecommon'
import { verifierMessage as _verifierMessage } from '@dugrema/millegrilles.common/lib/validateurMessage'

var _certificatCaForge = null,
    _certificateStore = null

function init(caPem) {
  _certificatCaForge = forgePki.certificateFromPem(caPem)
  _certificateStore = new CertificateStore(_certificatCaForge)
}

function verifierCertificat(chainePem, dateValidation) {
  return _certificateStore.verifierChaine(chainePem, {validityCheckDate: dateValidation})
}

async function verifierMessage(message) {
  const certificat = message['_certificat']
  const estampille = new Date(message['en-tete'].estampille * 1000)
  const certValide = verifierCertificat(certificat, estampille)

  if(!certValide) {
    var err = new Error("Certificat invalide")
    err.code = 1
    err.fields = ['_certificat']
    throw err
  }

  try {
    const certForge = forgePki.certificateFromPem(certificat[0])
    await _verifierMessage(message, certForge)
  } catch(err) {
    console.error("Erreur validation message", err)
    const errObj = new Error(''+err)
    errObj.cause = err
    errObj.code = 2
    errObj.fields = ['hachage_contenu', '_signature']
    throw errObj
  }

  return true
}

comlinkExpose({
  init, verifierMessage,
})
