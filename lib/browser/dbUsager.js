const { openDB: _openDB } = require('idb')
const { preparerCleSecreteSubtle } = require('../chiffrage')

const STORE_CLES_CONTENU = 'clesContenu',
      STORE_CLES_USAGER = 'cles',
      STORE_CLES_DECHIFFREES = 'clesDechiffrees',
      VERSION_COURANTE = 4

function openDB(nomDB, opts) {
  opts = opts || {}

  if(opts.upgrade) {
    return _openDB(nomDB, VERSION_COURANTE, {
      upgrade(db, oldVersion) {
        createObjectStores(db, oldVersion)
      },
      blocked() {
        console.error("OpenDB %s blocked", nomDB)
      },
      blocking() {
        console.warn("OpenDB, blocking")
      }
    })
  } else {
    // console.debug("Ouverture DB sans upgrade usager : %s", nomDB)
    return _openDB(nomDB)
  }
}

function createObjectStores(db, oldVersion) {
  console.debug("dbUsagers upgrade, DB object (version %s): %O", oldVersion, db)
  switch(oldVersion) {
    case 0:
    case 1:
      db.createObjectStore(STORE_CLES_USAGER)
    case 2:
      db.createObjectStore(STORE_CLES_CONTENU)
    case 3:
      db.createObjectStore(STORE_CLES_DECHIFFREES)
      break
    case 4: // Plus recent, rien a faire
      break
    default:
      console.warn("createObjectStores Default..., version %O", oldVersion)
  }
}

async function getCleContenu(nomUsager, hachage_bytes) {

  const nomDB = 'millegrilles.' + nomUsager
  const db = await openDB(nomDB)

  // console.debug("getCleContenu : usager:%s hachage_bytes:%s", nomUsager, hachage_bytes)

  // const tx = await db.transaction(TABLE_CLES_SECRETES, 'readonly')
  var cleContenu = null
  try {
    const store = db.transaction(STORE_CLES_CONTENU, 'readonly').objectStore(STORE_CLES_CONTENU)
    cleContenu = await store.get(hachage_bytes)
  } catch(err) {
    console.warn("Erreur getCleContenu : %O", err)
    return
  }

  // console.debug("getCleContenu : usager:%s hachage_bytes:%s = %O", nomUsager, hachage_bytes, cleContenu)

  return cleContenu
}

async function saveCleContenu(nomUsager, hachage_bytes, cleContenu) {
  const nomDB = 'millegrilles.' + nomUsager

  // console.debug("Save cle usager %s, fuuid %s", nomUsager, hachage_bytes)
  const db = await openDB(nomDB)
  const storeUpdate = db.transaction(STORE_CLES_CONTENU, 'readwrite').objectStore(STORE_CLES_CONTENU);
  return storeUpdate.put(cleContenu, hachage_bytes)
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

  console.debug("Conserver cle secrete pour fuuid %s : %O", hachage_bytes, data)

  return db.transaction(STORE_CLES_DECHIFFREES, 'readwrite')
    .objectStore(STORE_CLES_DECHIFFREES)
    .put(data, hachage_bytes)
}

async function getCleDechiffree(nomUsager, hachage_bytes) {
  const nomDB = 'millegrilles.' + nomUsager
  try {
    const db = await openDB(nomDB)
    const store = db.transaction(STORE_CLES_DECHIFFREES, 'readonly').objectStore(STORE_CLES_DECHIFFREES)
    return await store.get(hachage_bytes)
  } catch(err) {
    console.warn("Erreur getCleDechiffree : %O", err)
  }
}

async function clearClesContenu(nomUsager) {
  const nomDB = 'millegrilles.' + nomUsager

  const db = await openDB(nomDB)
  // console.debug("Reset des cles de contenu sauvegardees localement", nomUsager)

  await db.clear(STORE_CLES_CONTENU)
}

async function getCertificats(nomUsager, opts) {
  opts = opts || {}

  const nomDB = 'millegrilles.' + nomUsager
  const db = await openDB(nomDB, opts)

  // console.debug("Database %O", db)
  try {
    const tx = await db.transaction(STORE_CLES_USAGER, 'readonly')
    const store = tx.objectStore(STORE_CLES_USAGER)
    const certificat = (await store.get('certificat'))
    const fullchain = (await store.get('fullchain'))
    await tx.done

    return {certificat, fullchain}
  } catch(err) {
    console.error("getCertificats : %O", err)
    db.close()
  }
}

async function getClesPrivees(nomUsager) {

  const nomDB = 'millegrilles.' + nomUsager
  const db = await openDB(nomDB)

  // console.debug("Database %O", db)
  const tx = await db.transaction(STORE_CLES_USAGER, 'readonly')
  const store = tx.objectStore(STORE_CLES_USAGER)
  const dechiffrer = (await store.get('dechiffrer'))
  const signer = (await store.get('signer'))
  await tx.done

  return {dechiffrer, signer}
}

async function getCsr(nomUsager) {

  const nomDB = 'millegrilles.' + nomUsager
  const db = await openDB(nomDB)

  // console.debug("Database %O", db)
  const tx = await db.transaction(STORE_CLES_USAGER, 'readonly')
  const store = tx.objectStore(STORE_CLES_USAGER)
  const csr = (await store.get('csr'))
  await tx.done

  return {csr}
}

async function resetCertificatPem(nomUsager, opts) {
  if(!opts) opts = {}

  const nomDB = 'millegrilles.' + nomUsager

  const db = await openDB(nomDB, {upgrade: true})
  console.debug("Reset du cerfificat de navigateur usager (%s)", nomUsager)

  const txUpdate = db.transaction(STORE_CLES_USAGER, 'readwrite');
  const storeUpdate = txUpdate.objectStore(STORE_CLES_USAGER);
  return Promise.all([
    storeUpdate.delete('certificat'),
    storeUpdate.delete('fullchain'),
    storeUpdate.delete('csr'),
    storeUpdate.delete('signer'),
    storeUpdate.delete('dechiffrer'),
    storeUpdate.delete('public'),
    txUpdate.done,
  ])

}

module.exports = {
  openDB,
  getCertificats, getClesPrivees, getCsr, resetCertificatPem,
  getCleContenu, saveCleContenu, clearClesContenu,
  saveCleDechiffree, getCleDechiffree,
  createObjectStores,
}
