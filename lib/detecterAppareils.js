// Detection d'appareils media (camera, son, etc)
export async function detecterAppareilsDisponibles() {
  return navigator.mediaDevices.enumerateDevices().then(gotDevices)
}

// Capacites connues : audioinput, audiooutput, videoinput
function gotDevices(deviceInfos) {

  const appareils = {}

  for (var i = 0; i !== deviceInfos.length; ++i) {
    var deviceInfo = deviceInfos[i];
    var option = document.createElement('option');
    option.value = deviceInfo.deviceId;
    appareils[deviceInfo.kind] = true
  }

  return appareils
}

/* https://stackoverflow.com/questions/5573096/detecting-webp-support */
export function support_format_webp() {
  var elem = document.createElement('canvas');

  if (!!(elem.getContext && elem.getContext('2d'))) {
    // was able or not to get WebP representation
    return elem.toDataURL('image/webp').indexOf('data:image/webp') == 0;
  }
  else {
    // very old browser like IE 8, canvas not supported
    return false;
  }
}
