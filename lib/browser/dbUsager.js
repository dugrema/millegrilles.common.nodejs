const { openDB } = require('idb')
const { preparerCleSecreteSubtle } = require('../chiffrage')

const DB_NAME = 'millegrilles',
      STORE_USAGERS = 'usagers',
      STORE_CLES_DECHIFFREES = 'clesDechiffrees',
      VERSION_COURANTE = 1,
      MAX_AGE_DEFAUT = 6 * 60 * 60  // 6h en secondes

// Structure base de donnees
// usagers = {
//   nomUsager, // Cle
//   userId, csr,
//   dechiffrer, signer, public,
//   certificat: [str],
// }

function ouvrirDB(opts) {
  opts = opts || {}

  if(opts.upgrade) {
    return openDB(DB_NAME, VERSION_COURANTE, {
      upgrade(db, oldVersion) {
        createObjectStores(db, oldVersion)
      },
      blocked() {
        console.error("OpenDB %s blocked", DB_NAME)
      },
      blocking() {
        console.warn("OpenDB, blocking")
      }
    })
  } else {
    console.debug("Ouverture DB sans upgrade usager : %s", DB_NAME)
    return openDB(DB_NAME)
  }
}

function createObjectStores(db, oldVersion) {
  console.debug("dbUsagers upgrade, DB object (version %s): %O", oldVersion, db)
  switch(oldVersion) {
    case 0:
      db.createObjectStore(STORE_USAGERS, {keyPath: 'nomUsager'})
      db.createObjectStore(STORE_CLES_DECHIFFREES, {keyPath: 'hachage_bytes'})
    case 1: // Plus recent, rien a faire
      break
    default:
      console.warn("createObjectStores Default..., version %O", oldVersion)
  }
}

async function saveCleDechiffree(nomUsager, hachage_bytes, cleSecrete, cleInfo) {
  const nomDB = 'millegrilles.' + nomUsager
  const db = await openDB(nomDB)

  // Preparer une cle secrete non-exportable
  const data = {
    cleSecrete,
    iv: cleInfo.iv,
    tag: cleInfo.tag,
    format: cleInfo.format,
    date: new Date(),
  }

  // console.debug("Conserver cle secrete pour fuuid %s : %O", hachage_bytes, data)

  return db.transaction(STORE_CLES_DECHIFFREES, 'readwrite')
    .objectStore(STORE_CLES_DECHIFFREES)
    .put(data, hachage_bytes)
}

async function getCleDechiffree(nomUsager, hachage_bytes) {
  // const nomDB = 'millegrilles.' + nomUsager
  try {
    const db = await ouvrirDB()
    const store = db.transaction(STORE_CLES_DECHIFFREES, 'readonly').objectStore(STORE_CLES_DECHIFFREES)
    return await store.get(hachage_bytes)
  } catch(err) {
    console.warn("Erreur getCleDechiffree : %O", err)
  }
}

async function getUsager(nomUsager, opts) {
  opts = opts || {}
  const db = await ouvrirDB(opts)
  return lireUsager(db, nomUsager)
}

async function updateUsager(nomUsager, params, opts) {
  opts = opts || {}
  const db = await ouvrirDB(opts)
  let usager = await lireUsager(db, nomUsager)
  if(!usager) usager = {}
  const updateUsager = {...usager, ...params, nomUsager}
  console.debug("Update usager %s: %O", nomUsager, updateUsager)
  const tx = await db.transaction(STORE_USAGERS, 'readwrite')
  const store = tx.objectStore(STORE_USAGERS)
  const resultats = await Promise.all([
    // store.add(updateUsager),
    store.put(updateUsager),
    tx.done
  ])
  console.debug("Resultats update DB : %O", resultats)
  return resultats[0]
}

async function lireUsager(db, nomUsager) {
  const tx = await db.transaction(STORE_USAGERS, 'readonly')
  const store = tx.objectStore(STORE_USAGERS)
  const resultats = await Promise.all([store.get(nomUsager), tx.done])
  return resultats[0]
}

async function getListeUsagers() {
  const db = await ouvrirDB({upgrade: true})
  const tx = await db.transaction(STORE_USAGERS, 'readonly')
  const store = tx.objectStore(STORE_USAGERS)
  const promises = await Promise.all([store.getAllKeys(), tx.done])
  return promises[0].sort()
}

async function supprimerUsager(nomUsager) {
  const db = await ouvrirDB({upgrade: true})
  const tx = await db.transaction(STORE_USAGERS, 'readwrite')
  const store = tx.objectStore(STORE_USAGERS)
  const promises = await Promise.all([store.delete(nomUsager), tx.done])
  return promises[0]
}

async function getClesPrivees(nomUsager) {

  // const nomDB = 'millegrilles.' + nomUsager
  const db = await ouvrirDB()

  // console.debug("Database %O", db)
  const tx = await db.transaction(STORE_CLES_USAGER, 'readonly')
  const store = tx.objectStore(STORE_CLES_USAGER)
  const dechiffrer = (await store.get('dechiffrer'))
  const signer = (await store.get('signer'))
  await tx.done

  return {dechiffrer, signer}
}

async function getCsr(nomUsager) {

  // const nomDB = 'millegrilles.' + nomUsager
  const db = await ouvrirDB()

  // console.debug("Database %O", db)
  const tx = await db.transaction(STORE_CLES_USAGER, 'readonly')
  const store = tx.objectStore(STORE_CLES_USAGER)
  const csr = (await store.get('csr'))
  await tx.done

  return {csr}
}

async function entretienCache(nomUsager, opts) {
  /* Effectue l'entretien des caches de cles */
  opts = opts || {}
  if(!nomUsager) return

  const maxAge = (opts.maxAge || MAX_AGE_DEFAUT) * 1000  // convertir en millisecs
  const tempsExpiration = new Date().getTime() - maxAge

  await Promise.all([
    entretienCacheClesSecretes(nomUsager, tempsExpiration, opts),
    entretienCacheFichiersDechiffres(tempsExpiration, opts),
  ])
}

async function entretienCacheClesSecretes(nomUsager, tempsExpiration, opts) {
  opts = opts || {}
  const nomDB = 'millegrilles.' + nomUsager
  const db = await ouvrirDB()

  // console.debug("Entretien table de caches IndexedDB usager (%s), purger elements < %O", nomUsager, tempsExpiration)

  let cursor = await db.transaction(STORE_CLES_DECHIFFREES, 'readonly').store.openCursor()
  const clesExpirees = []
  while(cursor) {
    // console.debug("Cle %s = %O", cursor.key, cursor.value)
    const dateCle = cursor.value.date
    if(dateCle.getTime() < tempsExpiration) {
      clesExpirees.push(cursor.key)
    }
    cursor = await cursor.continue()  // next
  }

  if(clesExpirees.length > 0) {
    // console.debug("Nettoyage de %d cles expirees", clesExpirees.length)
    const txUpdate = await db.transaction(STORE_CLES_DECHIFFREES, 'readwrite')
    const storeUpdate = txUpdate.objectStore(STORE_CLES_DECHIFFREES)
    const promises = clesExpirees.map(cle=>{
      return storeUpdate.delete(cle)
    })
    promises.push(txUpdate.done)  // Marqueur de fin de transaction
    await Promise.all(promises)
    // console.debug("Nettoyage cles complete")
  }
}

async function entretienCacheFichiersDechiffres(tempsExpiration, opts) {
  const cache = await caches.open('fichiersDechiffres')
  const keys = await cache.keys()
  for await (let key of keys) {
    const cacheObj = await cache.match(key)
    const headers = {}
    for await(let h of cacheObj.headers.entries()) {
      headers[h[0]] = h[1]
    }

    // Utiliser header special 'date' injecte par consignationfichiers
    let tempsCache = 0
    try { tempsCache = new Date(headers.date).getTime() } catch(err) {/*OK*/}

    // console.debug("Cache %s = %O date %s (Headers: %O)", key, cacheObj, tempsCache, headers)
    if(tempsCache < tempsExpiration) {
      // console.debug("Nettoyer fichier dechiffre expire : %s", key)
      await cache.delete(key)
    }
  }
}

module.exports = {
  ouvrirDB, getUsager, updateUsager, getListeUsagers, supprimerUsager,
  saveCleDechiffree, getCleDechiffree,
  entretienCache,
}
