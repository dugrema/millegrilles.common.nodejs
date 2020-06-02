import moment from 'moment-timezone';

export class DateFormatter {

  constructor() {
    this.date_default = 'YYYY/MM/DD';
    this.datetime_default = 'YYYY/MM/DD HH:mm:ss';
    this.datemonthhour_default  = 'MMM-DD HH:mm:ss';

    this.timezone_default = 'America/Toronto';
  }

  format_date(date) {
    // On assume que la date est en secondes (epoch).
    return moment(date*1000).tz(this.timezone_default).format(this.date_default);
  }

  format_datetime(date) {
    // On assume que la date est en secondes (epoch).
    return moment(date*1000).tz(this.timezone_default).format(this.datetime_default);
  }

  format_monthhour(date) {
    // On assume que la date est en secondes (epoch).
    return moment(date*1000).tz(this.timezone_default).format(this.datemonthhour_default);
  }

}

export class NumberFormatter {
  format_numberdecimals(number, decimals) {
    if(number) {
      return number.toFixed(decimals);
    }
    return;
  }
}

export class FileSizeFormatter {

  constructor() {
    this.kb = 1024;
    this.mb = this.kb*1024;
    this.gb = this.mb*1024;
    this.tb = this.gb*1024;
    this.precision = 3;
  }

  format(nbBytes) {
    let result, unite;
    if(nbBytes > this.tb) {
      result = (nbBytes/this.tb).toPrecision(this.precision);
      unite = 'Tb';
    } else if(nbBytes > this.gb) {
      result = (nbBytes/this.gb).toPrecision(this.precision);
      unite = 'Gb';
    } else if(nbBytes > this.mb) {
      result = (nbBytes/this.mb).toPrecision(this.precision);
      unite = 'Mb';
    } else if(nbBytes > this.kb) {
      result = (nbBytes/this.kb).toPrecision(this.precision);
      unite = 'kb';
    } else {
      result = nbBytes;
      unite = 'bytes';
    }

    return result + ' ' + unite;
  }
}
