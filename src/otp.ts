import forge from 'node-forge';

// HOTP.hmac
function getHotpHmac(secret: string, counter: string) {
  const counterBuffer = forge.util.hexToBytes(counter);
  const secretBuffer = forge.util.hexToBytes(secret);

  const hmac = forge.hmac.create();
  hmac.start('sha1', secretBuffer);
  hmac.update(counterBuffer);
  return hmac.digest().toHex();
}

// HOTP.truncate
function truncateHotp(hash: string) {
  const offset = parseInt(hash[39], 16) * 2;
  const p = parseInt(hash.substring(offset, offset + 8), 16);
  return p & 0x7fffffff;
}

// HOTP.hotp
function getHotp(secret: string, counter: string) {
  const hmac = getHotpHmac(secret, counter);
  return truncateHotp(hmac);
}

// TOTP.padTime
function padTotpTime(time: string) {
  // eslint-disable-next-line no-param-reassign
  while (time.length < 16) time = `0${time}`;
  return time;
}

// TOTP.time
function getTotpTime(time: number, timeStep: number) {
  return padTotpTime(Math.floor(time / timeStep).toString(16));
}

// TOTP.totp
function getTotp(secret: string, time: string, otpLength: number) {
  const totp = getHotp(secret, time).toString();
  return totp.substring(totp.length - otpLength, totp.length);
}

export interface AuthyRequestOtps {
  otp1: string;
  otp2: string;
  otp3: string;
}

// AuthyOtpGenerator.prototype.getOtps
export default function getOtps(
  secret: string,
  otpLength: number,
  otpTimeStep: number,
  movingFactorCorrection: number = 0,
): AuthyRequestOtps {
  // TOTP.getUnixTime
  const unixTime = Math.floor(new Date().getTime() / 1000) + movingFactorCorrection;

  const time0 = getTotpTime(unixTime, otpTimeStep);
  const time1 = getTotpTime(unixTime + otpTimeStep, otpTimeStep);
  const time2 = getTotpTime(unixTime + otpTimeStep * 2, otpTimeStep);

  const otp1 = getTotp(secret, time0, otpLength);
  const otp2 = getTotp(secret, time1, otpLength);
  const otp3 = getTotp(secret, time2, otpLength);

  return { otp1, otp2, otp3 };
}
