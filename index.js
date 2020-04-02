const express = require('express');
const app = express();
const morgan = require('morgan');
const cors = require('cors');
const path = require('path');
const rsa = require('../../uni/BIGDATACIBER/ciberseguridad/rsa/rsa-cybersecurity');
const bigconv = require('bigint-conversion');
const sha = require('object-sha');
const request = require('request');
const ___dirname = path.resolve();
var crypto = require('crypto');


global.puKey;
global.prKey;
global.Key;
global.mensaje;

async function claves() {
  const { publicKey, privateKey } = await rsa.generateRandomKeys(3072);

  puKey = publicKey;
  prKey = privateKey;

};



// settings
app.set('port', process.env.PORT || 4000);
app.set('json spaces', 2);

// middleware
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors());



app.listen(app.get('port'), () => {
    // claves();
    console.log("Soy Bob");
    claves();
    console.log(`Server on port ${app.get('port')}`);
  });
// routes



app.get('/key', (req, res) => {

  class PublicKey {
    constructor(e, n) {
      this.e = bigconv.bigintToHex(e);
      this.n = bigconv.bigintToHex(n);
    }
  }

  publicKey = new PublicKey(
    puKey.e,
    puKey.n
  )

  res.status(200).send(publicKey);

});


app.post("/mensaje1", async (req, res) => {

  console.log("Entramos");
  clientePublicKey = new rsa.PublicKey(bigconv.hexToBigint(req.body.mensaje.e), bigconv.hexToBigint(req.body.mensaje.n));
  console.log(clientePublicKey);
  console.log("ahora vamos a verificar el hash");
  if ( await verifyHash(clientePublicKey) == true) {

    Key = req.body.mensaje.body.msg;
    console.log(Key);

    const body = {
      type: '2',
      src: 'B',
      dst: 'A',
    }

    const digest = await digestHash(body);
console.log("ahora vamos a firmar");
    const pr = bigconv.bigintToHex(prKey.sign(bigconv.textToBigint(digest)));

    res.status(200).send({
      body, pr
    });

  } else {
    res.status(400).send("No se ha podido verificar al cliente A");
  }

  async function digestHash(body){
    const d = await sha.digest(body, 'SHA-256');
    return d;
  }

  async function verifyHash(clientePublicKey) {
    const hashBody = await sha.digest(req.body.mensaje.body, 'SHA-256')

    console.log(hashBody);
    console.log(bigconv.bigintToText(clientePublicKey.verify(bigconv.hexToBigint(req.body.mensaje.po))))
    var verify = false;

    if (hashBody == bigconv.bigintToText(clientePublicKey.verify(bigconv.hexToBigint(req.body.mensaje.po)))) {
      verify = true
    }
    console.log(verify);

    return verify
  }

});

app.get('/avisobob', (req, res) => {

  res.status(200).send({mensaje : 'corecto'});
   getTTPclave();

});


function getTTPclave()
{
  request('http://localhost:2000/claveparabob', { json: true }, (err, res, body) => {
    if (err) { return console.log(err); }

    console.log(body.key);
    console.log(body.iv);

    decrypt(body.key, body.iv);


    // await crypto.subtle.decrypt(
//   {
//       name: "AES-CBC",
//       iv, //The initialization vector you used to encrypt
//   },
//   this.key, //from generateKey or importKey above
//   encrypt //ArrayBuffer of the data
// )
// .then(function(decrypted){
//   //returns an ArrayBuffer containing the decrypted data
//   console.log(new Uint8Array(decrypted));
//  des =   new Uint8Array(decrypted);
// })

// var as = this.ab2str(des);
// console.log(as);
    
  });

}

function decrypt(password,iv){
  var decipher = crypto.createDecipher('aes-256-cbc',password,iv)
  var dec = decipher.update(Key,'hex','utf8')
  dec += decipher.final('utf8');
  console.log(dec);
  return dec;
}