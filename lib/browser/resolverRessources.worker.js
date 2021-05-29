import axios from 'axios'
import path from 'path'
import {gunzip} from 'zlib'
import {preparerCertificateStore, verifierSignatureMessage} from '@dugrema/millegrilles.common/lib/pki2'
import {verifierIdmg} from '@dugrema/millegrilles.common/lib/idmg'
import mimetypeExtensions from '@dugrema/millegrilles.common/lib/mimetype_ext.json'

var _etatCdns = {},
    _siteId,
    _ipnsId,
    _siteConfiguration,
    _proxySetSiteConfiguration,
    _certificateStore,
    _idmg,
    _cdnCourant,
    _intervalVerificationConnexions,
    _compteurGetErreurs400 = 0,
    _compteurGetErreurs500 = 0

const ETAT_INACTIF = 0,
      ETAT_INIT    = 1,
      ETAT_ACTIF   = 2,
      ETAT_ERREUR  = 3

const LIMITE_ERREURS = 3

export async function appliquerSiteConfiguration(siteConfiguration) {
  // console.debug('!!! resolverRessources.setSiteConfiguration update : %O', siteConfiguration)
  _siteConfiguration = siteConfiguration

  if(!_certificateStore) {
    await chargerCertificateStore(siteConfiguration)
  }

  // console.debug("Set Site config : %O", siteConfiguration)
  _cdnCourant = mergeCdns(_siteConfiguration.cdns)
  // console.debug("CDNs initialises, commencer a verifier les sources")
}

function mergeCdns(cdns) {
  const cdnIdsConnus = Object.keys(_etatCdns)
  const cdnIdsRecus = cdns.reduce((acc, item)=>{
    return [...acc, item.cdn_id]
  }, [])

  // Ajouter / maj configuration des CDNs
  cdns.forEach(item=>{
    const cdnId = item.cdn_id
    if(!cdnIdsConnus.includes(cdnId)) {
      // Nouveau, ajouter
      _etatCdns[cdnId] = {config: item, etat: ETAT_INIT, tempsReponse: -1}
    } else {
      // Deja connu, on met a jour la configuration seulement
      _etatCdns[cdnId].config = item
    }
  })

  // Marquer CDN retire comme inactifs
  for(let cdnId in _etatCdns) {
    if(!cdnIdsRecus.includes(cdnId)) {
      _etatCdns[cdnId].etat = ETAT_INACTIF
    }
  }

  // console.debug("Etat CDNS apres maj : %O", _etatCdns)
  var opts = {}
  if(!_cdnCourant) opts.initial = true  // S'accroche au premier CDN qui repond
  return verifierConnexionCdns(opts)  // Conserver promise pour initialiser CDN
}

export async function chargerMappingSite(url) {
  // Le mapping est un fichier index.json accessible a la racine de tous les CDN
  // et du code deploye de Vitrine/Place,
  const reponse = await getUrl(url, {noverif: true})
  const mappingSite = reponse.data

  await chargerCertificateStore(mappingSite)
  console.debug("Chargement certificat store complete")

  return mappingSite
}

export async function chargerSiteConfiguration(cdns, mappingSite, proxySetSiteConfiguration) {
  // Conserver le siteId pour verifications des CDNs
  _siteId = mappingSite.site_id
  _ipnsId = mappingSite.ipns_id
  _proxySetSiteConfiguration = proxySetSiteConfiguration

  // Merge les CDNs initiaux et fetch la configuration (tout en un)
  await mergeCdns(cdns)

  if(!_intervalVerificationConnexions) {
    // Demarrer interval entretien connexion ressources
    _intervalVerificationConnexions = setInterval(verifierConnexionCdns, 300000)
  }

  await _cdnCourant
  console.debug("Site configuration : %O", _siteConfiguration)
  return _siteConfiguration
}

export async function rechargerSiteConfiguration() {
  console.debug("Site configuration : %O", _siteConfiguration)

}

export async function getUrl(url, opts) {
  opts = opts || {}
  const cdn = opts.cdn || {}

  if(url.endsWith('.json') && ['awss3'].includes(cdn.type_cdn)) {
    url = url + '.gz'
  }

  var responseType = opts.responseType
  if(responseType === 'json.gzip') {
    // On va decoder le fichier et le parser
    responseType = 'blob'
  }

  const axiosParams = {
    method: 'get',
    url,
    timeout: opts.timeout || 30000,
    responseType,
  }

  var data, status
  try {
    const reponse = await axios(axiosParams)
    data = reponse.data
    status = reponse.status
  } catch(err) {
    console.error("Erreur axios sur getUrl : %O", err)

    // TODO : verifier si on doit changer de CDN
    // Si on a un timeout, tenter de trouver nouveau CDN

    if(err.status >= 400 && err.status < 500) {
      // Si on a une erreur 400-500, augmenter compteur jusqu'a la limite puis trouver nouveau CDN
      if(_compteurGetErreurs400++ > LIMITE_ERREURS) {
        verifierConnexionCdns({initial: true})  // Trouver rapidement une connexion fonctionnelle
      }
    } else if(err.status >= 500 && err.status < 600) {
      // Si on a une erreur 400-500, augmenter compteur jusqu'a la limite puis trouver nouveau CDN
      if(_compteurGetErreurs500++ > LIMITE_ERREURS) {
        verifierConnexionCdns({initial: true})  // Trouver rapidement une connexion fonctionnelle
      }
    }

    throw err
  }

  if(opts.responseType === 'json.gzip') {
    // Extraire le resultat et transformer en dict
    const responseStr = await unzipResponse(data)
    data = JSON.parse(responseStr)
  }

  if(!opts.noverif) {
    // Verifier la signature de la ressource
    let signatureValide
    try {
      signatureValide = await verifierSignatureMessage(data, data._certificat, _certificateStore)
    } catch(err) {
      console.error("Erreur verification resultat : %O", data)
    }
    if(!signatureValide) {
      throw new Error(`Signature ${url} invalide`)
    }
    // console.debug("Signature %s est valide", url)
  }

  return {status, data}
}

export async function getSection(uuidSection, typeSection) {
  if(!await _cdnCourant) throw new Error("Aucun CDN n'est disponible")

  const typeCdn = _cdnCourant.config.type_cdn
  var urlComplet, opts = {}
  if(typeCdn === 'ipfs') {
    const ipfsMapping = _siteConfiguration.ipfs_map
    console.debug("IPFS map : %O", ipfsMapping)
    if(ipfsMapping) {
      const cid = ipfsMapping[uuidSection]
      urlComplet = 'ipfs://' + cid
      opts.timeout = 120000
      opts.responseType = 'json.gzip'
    } else {
      console.warn("IPFS map de sections n'est pas disponible dans _siteConfiguration")
    }
  } else if(typeCdn === 'ipfs_gateway') {
    const accessPointUrl = _cdnCourant.config.access_point_url
    const ipnsMapping = _siteConfiguration.ipns_map
    console.debug("IPNS map : %O", ipnsMapping)
    if(ipnsMapping) {
      const ipns_id = ipnsMapping[uuidSection]
      urlComplet = accessPointUrl + '/ipns/' + ipns_id
      opts.timeout = 120000
      opts.responseType = 'json.gzip'
    } else {
      console.warn("IPNS map de sections n'est pas disponible dans _siteConfiguration")
    }
  } else {
    const accessPointUrl = _cdnCourant.config.access_point_url
    var urlRessource = ''
    switch(typeSection) {
      case 'fichiers':
        urlRessource = '/data/fichiers/' + uuidSection + '.json'
        break
      case 'pages':
        urlRessource = '/data/pages/' + uuidSection + '.json'
        break
      case 'forum':
        urlRessource = '/data/forums/' + uuidSection + '.json'
        break
      default:
        console.debug("Type section inconnue : %s", typeSection)
    }
    urlComplet = accessPointUrl + urlRessource
  }

  return getUrl(urlComplet, {...opts, cdn: _cdnCourant.config})
}

export async function resolveUrlFuuid(fuuid, fuuidInfo) {
  if(!_cdnCourant) throw new Error("Aucun CDN n'est disponible")
  const mimetype = fuuidInfo.mimetype

  const typeCdn = _cdnCourant.config.type_cdn
  if(typeCdn === 'ipfs') {
    if(fuuidInfo.cid) {
      return 'ipfs://' + fuuidInfo.cid
    } else {
      console.warn("FUUID %s, aucun CID defini pour IPFS %O", fuuid, fuuidInfo)
    }
  } else if(typeCdn === 'ipfs_gateway') {
    if(fuuidInfo.cid) {
      const accessPointUrl = _cdnCourant.config.access_point_url
      return accessPointUrl + '/ipfs/' + fuuidInfo.cid
    } else {
      console.warn("FUUID %s, aucun CID defini pour IPFS", fuuid)
    }
  } else if(typeCdn === 'awss3') {
    const accessPointUrl = _cdnCourant.config.access_point_url
    const ext = mimetypeExtensions[mimetype] || 'bin'
    const pathFuuid = path.join('fichiers/public', fuuid + '.' + ext)
    const urlRessource = accessPointUrl + '/' + pathFuuid
    return urlRessource
  } else if(typeCdn === 'mq') {
    const accessPointUrl = _cdnCourant.config.access_point_url
    const urlBase = new URL(accessPointUrl)
    const pathFuuid = path.join('/fichiers/public', fuuid)
    urlBase.pathname = pathFuuid
    return ''+urlBase
  } else {
    const accessPointUrl = _cdnCourant.config.access_point_url
    const part1 = fuuid.slice(0, 5),
          part2 = fuuid.slice(5, 7)
    const ext = mimetypeExtensions[mimetype] || 'bin'

    const pathFuuid = path.join('fichiers/public', part1, part2, fuuid + '.' + ext)

    const urlRessource = accessPointUrl + '/' + pathFuuid
    return urlRessource
  }
}

async function verifierConnexionCdns(opts) {
  opts = opts || {}
  /* Parcours les CDN et trouve ceux qui sont actifs. */
  // console.debug("!!! debut verifierConnexionCdns")

  // Extraire CDN en ordre de preference de la configuration
  console.debug("VerifierConnexionCdns : _siteId %s, _siteConfiguration %O, _etatCdns %O",
    _siteId, _siteConfiguration, _etatCdns)
  let cdnIds
  if(_siteConfiguration) {
    cdnIds = _siteConfiguration.cdns.reduce((acc, item)=>{return [...acc, item.cdn_id]}, [])
  } else {
    cdnIds = Object.values(_etatCdns).map(item=>item.config.cdn_id)
  }

  // Verifier la presence de path/index.json sur chaque CDN
  var promisesCdns = []
  for await (let cdnId of cdnIds) {
    const etatCdn = _etatCdns[cdnId]
    const typeCdn = etatCdn.config.type_cdn
    chargerConfiguration(etatCdn)
    promisesCdns.push(etatCdn.promiseCheck)
  }

  // Attendre le premier CDN qui revient (le plus rapide)
  var cdnCourant
  if(opts.initial) {
    choisirCdn(promisesCdns)

    // Sur connexion initiale, on prend la premiere connexion qui est prete
    cdnCourant = await Promise.any(promisesCdns)
  } else {
    cdnCourant = choisirCdn(promisesCdns)
  }

  console.debug("Etat CDNs : %O\nCDN courant %O", _etatCdns, cdnCourant)
  _cdnCourant = cdnCourant
  return cdnCourant
}

function chargerConfiguration(etatCdn) {
  const cdnId = etatCdn.config.cdn_id
  const typeCdn = etatCdn.config.type_cdn
  switch(typeCdn) {
    case 'sftp':
    case 'awss3':
    case 'hiddenService':
    case 'mq':
    case 'manuel':
      etatCdn.promiseCheck = verifierEtatAccessPoint(cdnId)
      break
    case 'ipfs':
      etatCdn.promiseCheck = verifierEtatIpfs(cdnId)
      break
    case 'ipfs_gateway':
      etatCdn.promiseCheck = verifierEtatIpfsGateway(cdnId)
      break
    default:
      console.debug("Type CDN inconnu : %s", typeCdn)
  }

  return etatCdn.promiseCheck
}

export function rechargerConfiguration() {
  chargerConfiguration(_cdnCourant)
}

async function verifierEtatAccessPoint(cdnId) {
  const etatCdn = _etatCdns[cdnId],
        config = etatCdn.config

  const accessPointUrl = config.access_point_url
  if(accessPointUrl) {
    var urlRessource = accessPointUrl + '/data/sites/' + _siteId + '.json'

    console.debug("Verification %s", urlRessource)

    try {
      const dateDebut = new Date().getTime()
      const reponse = await getUrl(urlRessource, {cdn: config, timeout: 30000})
      await _proxySetSiteConfiguration(reponse.data)  // MAJ config (si plus recente)
      const tempsReponse = new Date().getTime()-dateDebut
      etatCdn.etat = ETAT_ACTIF
      etatCdn.tempsReponse = tempsReponse
    } catch(err) {
      etatCdn.etat = ETAT_ERREUR
      etatCdn.tempsReponse = -1
      console.error("Erreur access point : %O\n%O", etatCdn, err)
      throw err
    }
  } else {
    // CDN n'as pas d'access point, on ne peut pas l'utiliser
    etatCdn.etat = ETAT_INACTIF
    throw new Error(`CDN ${cdnId} n'a pas d'access point, il est inactif`)
  }

  return etatCdn
}

async function verifierEtatIpfs(cdnId) {
  const etatCdn = _etatCdns[cdnId]

  if(_ipnsId) {
    try {
      const url = "ipns://" + _ipnsId
      // console.debug("Verifier capacite d'acceder a IPFS directement avec %s", url)
      const dateDebut = new Date().getTime()

      const axiosParams = {
        method: 'get',
        url,
        timeout: 120000,
        responseType: 'blob',
      }

      const reponse = await axios(axiosParams)
      const tempsReponse = new Date().getTime()-dateDebut
      console.debug("verifierEtatIpfs: Reponse IPFS (%d ms): %O", tempsReponse, reponse)

      const responseStr = await unzipResponse(reponse.data)
      const data = JSON.parse(responseStr)
      console.debug("verifierEtatIpfs: data : %O", data)

      await _proxySetSiteConfiguration(data)  // MAJ config (si plus recente)

      etatCdn.etat = ETAT_ACTIF
      etatCdn.tempsReponse = tempsReponse
    } catch(err) {
      etatCdn.etat = ETAT_ERREUR
      etatCdn.tempsReponse = -1
      console.error("Erreur verifierEtatIpfs : %O\n%O", etatCdn, err)
      throw err
    }
  }

  return etatCdn
}

async function verifierEtatIpfsGateway(cdnId) {
  const etatCdn = _etatCdns[cdnId],
        config = etatCdn.config

  const accessPointUrl = config.access_point_url
  const ipnsId = _siteConfiguration.ipns_id
  if(ipnsId) {
    try {
      const url = accessPointUrl + '/ipns/' + ipnsId
      // console.debug("Verifier capacite d'acceder a IPFS directement avec %s", url)
      const dateDebut = new Date().getTime()
      const reponse = await axios({method: 'get', url, timeout: 120000})
      _proxySetSiteConfiguration(reponse.data)  // MAJ config (si plus recente)
      const tempsReponse = new Date().getTime()-dateDebut
      // console.debug("Reponse via IPNS: %O", reponse)

      etatCdn.etat = ETAT_ACTIF
      etatCdn.tempsReponse = tempsReponse
    } catch(err) {
      etatCdn.etat = ETAT_ERREUR
      etatCdn.tempsReponse = -1
      console.error("Erreur access point : %O\n%O", etatCdn, err)
      throw err
    }
  }

  return etatCdn
}

async function chargerCertificateStore(siteConfiguration) {
  // Preparer le certificate store avec le CA pour valider tous les .json telecharges
  const caPem = [...siteConfiguration['_certificat']].pop()  // Dernier certificat dans la liste

  // Valider le idmg - millegrille.pem === info.idmg
  const idmg = siteConfiguration['en-tete'].idmg
  verifierIdmg(idmg, caPem)
  console.info("IDMG verifie OK avec PEM = %s", idmg)

  try {
    const certificateStore = preparerCertificateStore(caPem)

    // Valider la signature de index.json (siteConfiguration)
    let signatureValide = await verifierSignatureMessage(
      siteConfiguration, siteConfiguration._certificat, certificateStore)

    if(!signatureValide) {
      console.error("Erreur verification index.json - signature invalide")
      throw new Error("Erreur verification index.json - signature invalide")
    }

    _certificateStore = certificateStore
    _idmg = idmg

  } catch(err) {
    console.error("Erreur verification index.json : %O", err)
    throw new Error("Erreur verification index.json - date certificat ou signature invalide")
  }

}

function unzipResponse(blob) {
  // const buffer = Buffer.from(stringBuffer, 'raw')
  return new Promise(async (resolve, reject)=>{
    const abData = await blob.arrayBuffer()
    gunzip(new Uint8Array(abData), (err, buffer) => {
      if (err) {
        console.error('Unzip Response error occurred:', err)
        return reject(err)
      }
      resolve(buffer.toString())
    })
  })
}

async function choisirCdn(promisesCdns) {
  const cdnsResultats = await Promise.allSettled(promisesCdns)
  console.debug("choisirCdn Resultat complet : %O", cdnsResultats)

  // CDN prefere
  const cdnIdPrefere = _siteConfiguration.cdns[0].cdn_id,
        cdnIdLocal = _siteConfiguration.cdn_id_local

  const cdns = cdnsResultats
    .filter(item=>item.status==='fulfilled')
    .map(item=>item.value)
    .filter(item=>item.etat === ETAT_ACTIF)
    .map(cdn=>{
      cdn.tempsPondere = cdn.tempsReponse

      // Donner un bonus de 250ms a la premiere connexion (config preferee)
      if(cdn.config.cdn_id === cdnIdPrefere) cdn.tempsPondere = cdn.tempsReponse - 250

      return cdn
    })

  // Trier les CDN par temps de reponse
  cdns.sort((a,b)=>{return a.tempsPondere - b.tempsPondere})
  // console.debug("Liste triee de CDNs %O", cdns)

  const cdnChoisi = cdns[0]
  console.debug("Nouveau CDN courant : %O", cdnChoisi)
  _cdnCourant = cdnChoisi

  // Reset compteur erreurs
  _compteurGetErreurs400 = 0
  _compteurGetErreurs500 = 0

  return cdnChoisi
}

export async function verifierSignature(message) {
  // Methode de verification de la signature d'un message
  let signatureValide
  try {
    signatureValide = await verifierSignatureMessage(message, message._certificat, _certificateStore)
  } catch(err) {
    console.error("Erreur verification resultat : %O", message)
  }
  if(!signatureValide) {
    throw new Error(`Signature message invalide`)
  }
  return signatureValide
}
