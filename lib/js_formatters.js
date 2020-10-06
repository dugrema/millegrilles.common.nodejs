function formatterDateString(date) {
  let year = date.getUTCFullYear();
  let month = date.getUTCMonth() + 1; if(month < 10) month = '0'+month;
  let day = date.getUTCDate(); if(day < 10) day = '0'+day;
  let hour = date.getUTCHours(); if(hour < 10) hour = '0'+hour;
  const dateFormattee = "" + year + month + day + hour;
  return dateFormattee
}

module.exports = {formatterDateString}
