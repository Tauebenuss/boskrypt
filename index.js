const chalk = require('chalk')
function comparePrint(shoudlbe, myimpl) {
  let overeenstemming = 0
  for (let i=0;i< shoudlbe.length;i++) {
    if (myimpl[i] == shoudlbe[i]) overeenstemming++; else break;
  }

  console.log('  myimpl: ', chalk.greenBright(myimpl.substring(0, overeenstemming)) + chalk.red(myimpl.substring(overeenstemming)))
  console.log('  should: ', chalk.blue(shoudlbe))
  console.log()
}

const crc = require('node-crc')
const crypto = require("crypto")
//console.log(crypto.getCiphers())



function getNullBytes(count) {
  return '\x00'.repeat(count)
}
const TEST_KEY = '7C524984DA2A43607483ED3EFF92365FFF1C374024961F83CDA14A8DECD3D93A'.toLowerCase()
const key = Buffer.from(TEST_KEY, 'hex')

const iv = 0x16FB7A1C
const timestamp = 0x8E83DB0D
const ivPadBuffer = Buffer.from("00".repeat(8), 'hex')
const ivWithTimestamp = Buffer.from(timestamp.toString(16) + iv.toString(16), 'hex')
const ivWithTimestampPadded = Buffer.concat([ ivWithTimestamp, ivPadBuffer ])
// right hash
const uncPayload = "Test"
console.log(uncPayload.length)
const uncPayloadHash = Buffer.from(crypto.createHash("sha1").update(uncPayload).digest('hex').substring(0,10), 'hex') // first 40bits. 2*40/8

let preparedPayload = "ENCR" + uncPayload + getNullBytes(16) // random null-fill

console.log('Key:')
comparePrint(TEST_KEY, key.toString('hex'))

console.log('IV with Timestamp:')
comparePrint(
  '8e83db0d16fb7a1c', // should
  ivWithTimestamp.toString('hex') // is
)

console.log('SHA1(Cleartext):')
comparePrint(
  '640ab2bae0', //should
  uncPayloadHash.toString('hex') // is
)


console.log('1) EncIndWithClearText', preparedPayload.length + ' bytes')
comparePrint(
  '454e43525465737400000000000000000000000000000000', // should 
  Buffer.from(preparedPayload).toString('hex') // is
)

let compressedPreparedPayload = preparedPayload.split('').map(x => { //foreach char run this
  return x.charCodeAt(0) //get byte
    .toString(2) // to base2/bcd/"binary"
    .padStart(8, '0') // pad to 8 digits (dec4 = 100 => 00000100)
    .split('') // to array
    .reverse() // reverse
    .join('') // back to string
    .substring(0, 7) //take first 7 chars
}).join('') //join to one complete string

//compressedPreparedPayload += '0'.repeat(8-(compressedPreparedPayload.length % 8))

let compressedPayload = []
for (let i=0;i<compressedPreparedPayload.length;i+=8) {
  let byte = parseInt(
    compressedPreparedPayload
    .substring(i, i+8) //select 8char chunk from bigstring
    .split('') // to array
    .reverse() // reverse
    .join(''), // back to string
  2) // parse from base2
  compressedPayload.push( byte ) //put in array
}
compressedPayload = Buffer.from(compressedPayload)

const toEncryptData = Buffer.concat([
  uncPayloadHash, compressedPayload
])
console.log('2) EncIndWithClearTextCompressed', compressedPayload.length + ' bytes')
comparePrint(
  '45e7504a2dcfe90000000000000000000000000000', //should
  compressedPayload.toString('hex') // is
)

console.log('toEncrypt', toEncryptData.length + ' bytes')
comparePrint(
  '640ab2bae0' + '45e7504a2dcfe90000000000000000000000000000', //should
  toEncryptData.toString('hex') // is
)

let encryptedPayload = crypto.createCipheriv('aes-256-ctr', key, ivWithTimestampPadded, {
}).update(toEncryptData)

//encryptedPayload = Buffer.from('TSos4dWkdWCStRAUKsL74PGTYg5wDH3SAEA==','base64')

const encrpytedIncludingIVandSHA1Checksum = Buffer.concat([
  ivWithTimestamp,
  encryptedPayload
])
console.log('3) Encrypted including IV and SHA1 checksum CTR mode', encrpytedIncludingIVandSHA1Checksum.length + ' bytes')
comparePrint(
  Buffer.from('joPbDRb7ehxTSos4dWkdWCStRAUKsL74PGTYg5wDH3SAEA==','base64').toString('hex'), // should
  encrpytedIncludingIVandSHA1Checksum.toString('hex') // is
)

// expected
// 8 byte 64bit IV + 40byte Encrypted Payload(containg 34byte of something and 6byte of whatever)


// 'joPbDRb7ehx' + 'TSos4dWkdWCStRAUKsL74PGTYg5wDH3SAEA=='
// 'joPbDRb7ehxTSos4dWkdWCStRAUKsL74PGTYg5wDH3SAEA==' length 48
// 8e83db0d16fb7a1c534a8b3875691d5824ad44050ab0bef83c64d8839c031f748010

//


let base64 = encrpytedIncludingIVandSHA1Checksum.toString('base64')
console.log('4) base64', base64.length + ' bytes')
comparePrint(
  'joPbDRb7ehxTSos4dWkdWCStRAUKsL74PGTYg5wDH3SAEA==', // should
  base64 // is
)