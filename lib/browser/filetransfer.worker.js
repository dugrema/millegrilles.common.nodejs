const path = require('path')
const axios = require('axios')
const {expose: comlinkExpose} = require('comlink')
const {v4: uuidv4} = require('uuid')
const { creerCipher } = require('../chiffrage')
const { getAcceptedFileReader, streamAsyncIterable } = require('../stream')

// Globals
// Structure uploads : {file: AcceptedFile, status=1, }
var _uploadsPending = [],
    _uploadEnCours = null,
    _uploadsCompletes = []

// Callback etat : (nbFichiersPending, pctFichierEnCours, {encours: uuid, complete: uuid})
var _callbackEtatUpload = null

const BATCH_SIZE = 1 * 1024 * 1024  // 1 MB

async function ajouterFichiersUpload(acceptedFiles) {
    for(let i=0; i<acceptedFiles.length; i++) {
        const file = acceptedFiles[i]
        console.debug("Ajouter upload : %O", file)

        let dateFichier = null
        try {
          dateFichier = Math.floor(file.lastModified / 1000)
        } catch(err) {
          console.warn("Erreur chargement date fichier : %O", err)
        }
    
        const transaction = {
          nom: file.name,
          mimetype: file.type,
          taille: file.size,
          dateFichier,
        }
    
        // if(uuid_collection) {
        //   transaction['cuuid'] = uuid_collection
        // }
    
        _uploadsPending.push({
          file,
          bytesUploade: 0,
          size: file.size,
          progres: 0,    // Pourcentage de progres
          status: 1,     // 1: pas demarre, 2: en cours, 3: succes, 4: echec
          correlation: uuidv4(),
          transaction,
        })

    }

    console.info("Uploads pending : %O", _uploadsPending)
    traiterUploads()  // Demarrer traitement si pas deja en cours
}

async function traiterUploads() {
    if(_uploadEnCours) return  // Rien a faire

    let complete = ''
    try {
        for(_uploadEnCours = _uploadsPending.pop(); _uploadEnCours; _uploadEnCours = _uploadsPending.pop()) {
            console.debug("Traitement fichier %O", _uploadEnCours)
            emettreEtat({complete}).catch(err=>(console.warn("Erreur maj etat : %O", err)))
            await uploadFichier()

            _uploadsCompletes.push(_uploadEnCours)
            complete = _uploadEnCours.correlation
            _uploadEnCours.complete = true
        }
    } catch(err) {
        console.error("Erreur PUT fichier : %O", err)
        _uploadEnCours.complete = true
    } finally {
        _uploadEnCours = null
        emettreEtat({complete}).catch(err=>(console.warn("Erreur maj etat : %O", err)))
    }

}

async function uploadFichier() {

    const correlation = _uploadEnCours.correlation

    console.debug("Traiter upload en cours : %O", _uploadEnCours)
    const reader = streamAsyncIterable(getAcceptedFileReader(_uploadEnCours.file), {batchSize: BATCH_SIZE})

    var position = 0
    for await (let batchContent of reader) {
        const pathUpload = path.join('/fichiers/upload/', ''+correlation, ''+position)
        position += batchContent.length
        const cancelTokenSource = axios.CancelToken.source()
        _uploadEnCours.cancelTokenSource = cancelTokenSource
        const reponse = await axios({
            url: pathUpload,
            method: 'PUT',
            headers: { 'content-type': 'application/data' },
            data: batchContent,
            onUploadProgress,
            cancelToken: cancelTokenSource.token,
        })
        _uploadEnCours.position = position
        _uploadEnCours.pctFichierEnCours = Math.floor(position/_uploadEnCours.size * 100)
        console.debug("Reponse upload %s position %d Pct: %d put block %O", correlation, position, _uploadEnCours.pctFichierEnCours, reponse)
        emettreEtat().catch(err=>(console.warn("Erreur maj etat : %O", err)))
    }
}

function onUploadProgress(progress) {
    const {loaded, total} = progress
    console.debug("Axios progress sur %s : %d/%d", _uploadEnCours.correlation, loaded, total)
    _uploadEnCours.batchLoaded = loaded
    _uploadEnCours.batchTotal = total
    if( !isNaN(loaded) && !isNaN(total) ) {
        const pctProgres = Math.floor(loaded / total * 100)
        _uploadEnCours.pctBatchProgres = pctProgres
    }
    emettreEtat().catch(err=>(console.warn("Erreur maj etat : %O", err)))
}

async function annulerUpload(correlation) {
    if(!_uploadEnCours) return  // Ok, upload n'est pas en cours
    _uploadEnCours.annuler = true
    if(_uploadEnCours.cancelTokenSource) {
        // Toggle annulation dans Axios
        _uploadEnCours.cancelTokenSource.cancel('Usager annule upload')
    }
}
  
async function emettreEtat(flags) {
    flags = flags || {}
    if(_callbackEtatUpload) {
        console.debug("Emettre etat")

        // const flags = {}
        let pctFichierEnCours = 0
        if(_uploadEnCours) {
            flags.encours = _uploadEnCours.correlation
            pctFichierEnCours = _uploadEnCours.pctFichierEnCours || 0
        }

        _callbackEtatUpload(
            _uploadsPending.length, 
            pctFichierEnCours, 
            flags,
            //{encours: uuid, complete: uuid},
        )
    }
}

function setCallbackUpload(cb) {
    _callbackEtatUpload = cb
}

comlinkExpose({
    ajouterFichiersUpload,
    setCallbackUpload,
    annulerUpload,
})