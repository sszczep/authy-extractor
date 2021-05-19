import qrcode, { QRCodeErrorCorrectionLevel } from 'qrcode';
import { promises as fs } from 'fs';
import path from 'path';
import { DecryptedToken } from './decrypt';

// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
export function generateTokenURI(token: DecryptedToken) {
  const period = token.digits === 7 ? 10 : 30;
  const name = encodeURIComponent(token.name);

  if (token.issuer === null) {
    return `otpauth://totp/${name}?secret=${token.decrypted_seed}&digits=${token.digits}&period=${period}`;
  }

  const issuer = encodeURIComponent(token.issuer);
  return `otpauth://totp/${issuer}%3A%20${name}?secret=${token.decrypted_seed}&issuer=${issuer}&digits=${token.digits}&period=${period}`;
}

export async function exportCSV(tokens: DecryptedToken[], output: string) {
  const outputFile = path.join(output, 'out.csv');

  const headers = ['Account name', 'Issuer', 'Secret', 'URI'];
  const rows = tokens
    .map((token) => {
      const { name, issuer, decrypted_seed } = token;
      const uri = generateTokenURI(token);

      // https://stackoverflow.com/a/4617967
      const fields = [name, issuer, decrypted_seed, uri].map((field) => {
        if (field === null) return '""';
        return `"${field.toString().replaceAll('"', '""')}"`;
      });

      return fields.join(',');
    })
    .join('\r\n');

  const csv = `${headers}\r\n${rows}`;

  await fs.writeFile(outputFile, csv);
}

export async function exportJSON(tokens: DecryptedToken[], output: string) {
  const outputFile = path.join(output, 'out.json');

  const json = JSON.stringify(
    tokens.map((token) => ({
      name: token.name,
      issuer: token.issuer,
      secret: token.decrypted_seed,
      uri: generateTokenURI(token),
    })),
    null,
    2,
  );

  await fs.writeFile(outputFile, json);
}

export async function exportQR(
  tokens: DecryptedToken[],
  output: string,
  correction: QRCodeErrorCorrectionLevel,
) {
  return Promise.all(
    tokens.map((token) => {
      const outputFile = path.join(output, `${token.name}.png`);
      return qrcode.toFile(outputFile, generateTokenURI(token), {
        errorCorrectionLevel: correction,
      });
    }),
  );
}
