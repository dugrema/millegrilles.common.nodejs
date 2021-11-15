const axios = require('axios')
const {expose: comlinkExpose} = require('comlink')
const {v4: uuidv4} = require('uuid')

// Globals
// Structure uploads : {file: AcceptedFile, status=1, }
var _uploadsPending = [],
    _uploadEnCours = null,
    _uploadsCompletes = []

// Callback etat : (nbFichiersPending, pctFichierEnCours, {encours: uuid, complete: uuid})
var _callbackEtatUpload = null

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
        }
    } catch(err) {
        console.error("Erreur PUT fichier : %O", err)
    } finally {
        _uploadEnCours = null
        emettreEtat({complete}).catch(err=>(console.warn("Erreur maj etat : %O", err)))
    }

}

async function uploadFichier() {

    const pathUpload = '/fichiers/upload'
    const ciphertext = 'test'
    const correlation = 'abcd-1234',
          position = 0

    const reponse = await axios({
        url: pathUpload,
        method: 'PUT',
        headers: { 'content-type': 'application/data' },
        data: ciphertext,
        onUploadProgress,
        // cancelToken: cancelTokenSource.token,
    })
    console.debug("Reponse upload %s position %d put block %O", correlation, position, reponse)
}

function onUploadProgress(progress) {
    console.debug("Upload progress : %O", progress)
}

async function emettreEtat(flags) {
    flags = flags || {}
    if(_callbackEtatUpload) {
        console.debug("Emettre etat")
        const pctFichierEnCours = 0

        // const flags = {}
        if(_uploadEnCours) {
            flags.encours = _uploadEnCours.correlation
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
})