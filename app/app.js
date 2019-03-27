const fs = require("fs");
let { Crypto } = require("@peculiar/webcrypto");
const xadesjs = require("xadesjs");
const { XMLSerializer } = require("xmldom-alpha");
const pem = require('pem');
const crypto = new Crypto();
const atob = require('atob');
let privateKey;
let certificate;
const xml = 
`<?xml version='1.0' encoding='UTF-8' standalone='no'?>
<dte:GTDocumento>
    <dte:SAT ClaseDocumento='dte'>
        <dte:DTE ID='DatosCertificados'>
            <dte:DatosEmision ID='DatosEmision'>
                <dte:DatosGenerales CodigoMoneda='USD' FechaHoraEmision='2019-03-25T19:24:15-06:00' NumeroAcceso='100016906' Tipo='FACT'/>
                <dte:Emisor AfiliacionIVA='GEN' CodigoEstablecimiento='1' CorreoEmisor='esau.morales@externosmp.com.mx' NITEmisor='47250763' NombreComercial='MANPOWER, SOCIEDAD ANONIMA' NombreEmisor='MANPOWER, SOCIEDAD ANONIMA'>
                    <dte:DireccionEmisor>
                        <dte:Direccion>7 Avenida 7-07 Zona 9 P.B.X.:(502)</dte:Direccion>
                        <dte:CodigoPostal>7070</dte:CodigoPostal>
                        <dte:Municipio>GUATEMALA</dte:Municipio>
                        <dte:Departamento>GUATEMALA</dte:Departamento>
                        <dte:Pais>GT</dte:Pais>
                    </dte:DireccionEmisor>
                </dte:Emisor>
                <dte:Receptor CorreoReceptor='' IDReceptor='CF' NombreReceptor='PEARSON EDUCACION DE MEXICO, S.A. DE C.V'>
                    <dte:DireccionReceptor>
                        <dte:Direccion>AVE. ANTONIO DOVALI JAIME No. 70 TORRE B PISO 6 0 ZEDEC ED PLAZA SANTA FE,ALVARO OBREGON, CIUDAD DE MEXICO, C.P. 01210 México modificado</dte:Direccion>
                        <dte:CodigoPostal>7330</dte:CodigoPostal>
                        <dte:Municipio/>
                        <dte:Departamento>GUATEMALA</dte:Departamento>
                        <dte:Pais>mx</dte:Pais>
                    </dte:DireccionReceptor>
                </dte:Receptor>
                <dte:Frases>
                    <dte:Frase CodigoEscenario='1' TipoFrase='1'/>
                    <dte:Frase CodigoEscenario='1' TipoFrase='2'/>
                </dte:Frases>
                <dte:Items>
                    <dte:Item BienOServicio='S' NumeroLinea='1'>
                        <dte:Cantidad>1</dte:Cantidad>
                        <dte:UnidadMedida>UD</dte:UnidadMedida>
                        <dte:Descripcion>ADMINISTRACION DE PERSONAL</dte:Descripcion>
                        <dte:PrecioUnitario>24152.16</dte:PrecioUnitario>
                        <dte:Precio>24152.16</dte:Precio>
                        <dte:Descuento>0.00</dte:Descuento>
                        <dte:Impuestos>
                            <dte:Impuesto>
                                <dte:NombreCorto>IVA</dte:NombreCorto>
                                <dte:CodigoUnidadGravable>1</dte:CodigoUnidadGravable>
                                <dte:MontoGravable>21564.42</dte:MontoGravable>
                                <dte:MontoImpuesto>2587.73</dte:MontoImpuesto>
                            </dte:Impuesto>
                        </dte:Impuestos>
                        <dte:Total>24152.16</dte:Total>
                    </dte:Item>
                </dte:Items>
                <dte:Totales>
                    <dte:TotalImpuestos>
                        <dte:TotalImpuesto NombreCorto='IVA' TotalMontoImpuesto='2587.73'/>
                    </dte:TotalImpuestos>
                    <dte:GranTotal>24152.15</dte:GranTotal>
                </dte:Totales>
            </dte:DatosEmision>
        </dte:DTE>
    </dte:SAT>
</dte:GTDocumento>`;

xadesjs.Application.setEngine("OpenSSL", crypto);

const pfx = fs.readFileSync("./key/llave.pfx");

pem.readPkcs12(pfx, { p12Password: "E/19/Fcs"}, (err, cert) => {
  if(err) return console.log(err);
  privateKey = b64ToBinary(removePFXComments(cert.key));
  certificate = removePFXComments(cert.cert);
  console.log('llave privada: ' + privateKey);
  console.log('certificado ' + certificate); 

});

function removePFXComments(pem) {
  let lines = pem.split('\n');
  let encoded = '';
  for (let i = 0; i < lines.length; i++) {
      if (lines[i].trim().length > 0 &&
          lines[i].indexOf('-----BEGIN CERTIFICATE-----') < 0 &&
          lines[i].indexOf('-----END CERTIFICATE') < 0 &&
          lines[i].indexOf('-----BEGIN RSA PRIVATE KEY-----') < 0 &&
          lines[i].indexOf('-----BEGIN RSA PUBLIC KEY-----') < 0 &&
          lines[i].indexOf('-----BEGIN PUBLIC KEY-----') < 0 &&
          lines[i].indexOf('-----END PUBLIC KEY-----') < 0 &&
          lines[i].indexOf('-----BEGIN PRIVATE KEY-----') < 0 &&
          lines[i].indexOf('-----END PRIVATE KEY-----') < 0 &&
          lines[i].indexOf('-----END RSA PRIVATE KEY-----') < 0 &&
          lines[i].indexOf('-----END RSA PUBLIC KEY-----') < 0) {
          encoded += lines[i].trim();
      }
  }
  return encoded;
}

function b64ToBinary(base64) {
  let raw = atob(base64);
  let rawLength = raw.length;
  let array = new Uint8Array(new ArrayBuffer(rawLength));

  for(let i = 0; i < rawLength; i++) {
    array[i] = raw.charCodeAt(i);
  }
  return array;
}

function SignXml(xmlString, algorithm) {
  return Promise.resolve()
    .then(() => {
      let xmlDoc = xadesjs.Parse(xmlString);
      let signedXml = new xadesjs.SignedXml();

      return signedXml.Sign(               // Signing document
        algorithm,                              // algorithm
        privateKey,                        // key
        xmlDoc,                                 // document
        {                                       // options
          keyValue: certificate,
          references: [
            { hash: "SHA-256", transforms: ["enveloped"] }
          ],
          productionPlace: {
            country: "Country",
            state: "State",
            city: "City",
            code: "Code",
          },
          signingCertificate: "MIIDUjCCAjqgAwIBAgIIKHiu5aG1hh8wDQYJKoZIhvcNAQELBQAwKTEMMAoGA1UEAwwDRkVMMQwwCgYDVQQKDANTQVQxCzAJBgNVBAYTAkdUMB4XDTE5MDIwNDIyMzc0NloXDTIxMDIwMzIyMzc0NlowKDERMA8GA1UEAwwINDcyNTA3NjMxEzARBgNVBAoMCnNhdC5nb2IuZ3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdVxwiNIFspNUUNzbfUw+WQG+41HSpnGfXcN/qM6l8jZR1DL3h1yXy25f5ossJIA0gRSGOZ2mpWIO4BipyaPjvD7OAp+FWodKtuYDUmV/6xys8Ms7vXL2HiTHlLAjEreSiGJ4AuiRgyg71PiJJHmtu6XI+9gDnEL2A25UpA7cVv1ADg4+dwqPEuHS8A4rdVv5cabjq/AroZPKr9eDi89D1qvYUmcCEfUSZZnI7h3iayPG99m18cZyCNxuOYqxS9albQ1J/pU2wjUU6MTgUQBCSfufg2Y3HlBTGEkLoLUm/B2rfuIfq6dlaSkzuKb6vYDWu3bXmH8FAk2/hNeLP7PpzAgMBAAGjfzB9MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUc73zilJsM5hZ1/fQrbFzjLRQSgowHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMB0GA1UdDgQWBBRAlY1NBdE7yXE13xfbLLBqlIW/PzAOBgNVHQ8BAf8EBAMCBeAwDQYJKoZIhvcNAQELBQADggEBAGHyOZabZbprnaeSC90XP197Z8ltlbfjEPKQrGUGFsgeXZhtB8nLIr7z5SdWwzVASMmbSVBmOTNGWZk0w73vGQ4QGtOD9hi8AdMCquZWmBW4oOl4Byq8KodTD10KCQXtWJOrXsQprs/YEQC4gOBr9Dj5COeKx37jXxNC0LO8ZXh37EquetJQuTAt+WTY1JK6vbbuDM217kHybPR5vfR4nKy9ko0v/01HMxBokbDT9wd7f8U67vP5UcCeR5cSK+JtJvIhpZww/e4OUFYMLLJcNaKf6T3SuNckgqm+SwHyBSPfbAdieq2q/nIdhJZppjGroxyt1mIRDHrImxwGURwDB4U="
        })
    }).then(signature => signature.toString());
}

SignXml(xml, { name: "ECDSA", hash: { name: "SHA-1" } }).then(res => {
  console.log(res);
  console.log('Se firmo el documento');
}).catch(err => {
  console.log(err);
  console.log(1);
});