import fs from 'fs';
import path from 'path'
import chalk from 'chalk'
import xmlFormat from 'xml-formatter'

import { CERT_OPTIONS, CERT_OPTIONS_KEYS, CRYPT_TYPES, CRYPT_TYPES_KEYS, UNDEFINED_VALUE } from './constants';

export const matchesCertType = (value: string, type: CRYPT_TYPES_KEYS) => {
  return CRYPT_TYPES[type] && CRYPT_TYPES[type].test(value);
}
  
export const resolveFilePath = (filePath: string) => {
  if (filePath.startsWith('saml-idp/')) {
    const resolvedPath = require.resolve(filePath.replace(/^saml\-idp\//, `${__dirname}/`));
    return fs.existsSync(resolvedPath) && resolvedPath;
  }

  if (fs.existsSync(filePath)) {
    return filePath;
  }
  
  if (filePath.startsWith('~/')) {
    let possiblePath;
    // Allows file path options to files included in this package, like config.js
    possiblePath = path.resolve(process.env.HOME!, filePath.slice(2));
    if (fs.existsSync(possiblePath)) {
      return possiblePath;
    } else {
     // for ~/ paths, don't try to resolve further
      return filePath;
    }
  }

  return ['.', __dirname]
    .map(base => path.resolve(base, filePath))
    .find(possiblePath => fs.existsSync(possiblePath));
}
    
export const makeCertFileCoercer = (type: CRYPT_TYPES_KEYS, description?: string, helpText?: string) => {
  return (value: string) => {
    if (matchesCertType(value, type)) {
      return value;
    }

    const filePath = resolveFilePath(value);
    if (filePath) {
    return fs.readFileSync(filePath)
    }

    throw new Error(
      chalk`{red Invalid / missing {bold ${description}}} - {yellow not a valid crypt key/cert or file path}${helpText ? '\n' + helpText : ''}`
    )
  };
}

export const getHashCode = (value: string) => {
  let hash = 0;
  let char;

  if (value.length == 0) return hash;

  for (let i = 0; i < value.length; i++) {
    char = value.charCodeAt(i);
    hash = ((hash<<5)-hash)+char;
    hash = hash & hash; // Convert to 32bit integer
  }

  return hash;
}

export const dedent = (str: string) => {
  // Reduce the indentation of all lines by the indentation of the first line
  const match = str.match(/^\n?( +)/);
  if (!match) {
    return str;
  }

  const indentRegExp = new RegExp(`\n${match[1]}`, 'g');

  return str.replace(indentRegExp, '\n').replace(/^\n/, '');
}

const formatOptionValue = (key: CERT_OPTIONS_KEYS, value: any) => {
  if (typeof value === 'string') {
    return value;
  }

  if (CERT_OPTIONS.includes(key)) {
    return chalk`${
      value.toString()
        .replace(/-----.+?-----|\n/g, '')
        .substring(0, 80)
    }{white …}`;
  }

  if (!value && value !== false) {
    return UNDEFINED_VALUE;
  }

  if (typeof value === 'function') {
    const lines = `${value}`.split('\n');
    return lines[0].slice(0, -2);
  }

  return `${JSON.stringify(value)}`;
}

export const prettyPrintXml = (xml: string, indent: number) => {
  // This works well, because we format the xml before applying the replacements
  const prettyXml = xmlFormat(xml, {indentation: '  '})
    // Matches `<{prefix}:{name} .*?>`
    .replace(/<(\/)?((?:[\w]+)(?::))?([\w]+)(.*?)>/g, chalk`<{green $1$2{bold $3}}$4>`)
    // Matches ` {attribute}="{value}"
    .replace(/ ([\w:]+)="(.+?)"/g, chalk` {white $1}={cyan "$2"}`);
  if (indent) {
    return prettyXml.replace(/(^|\n)/g, `$1${' '.repeat(indent)}`);
  }
  return prettyXml;
}