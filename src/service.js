'use strict';

/**
 * [EN]    Service for two-step PAdES (PDF) signing using PKCS#1 (external private key).
 *         The private key never leaves the client device; only the public certificate PEM is sent.
 *
 *         Flow:
 *           1. prepareSignature — sends documents + certificate to SolidSign; receives hashes + finalNonce.
 *           2. finalizeSignature — sends finalNonce + signed hashes; receives download links.
 *
 * [PT-BR] Serviço para assinatura PAdES (PDF) em dois passos com PKCS#1 (chave privada externa).
 *         A chave privada nunca sai do dispositivo do cliente; apenas o PEM do certificado é enviado.
 *
 *         Fluxo:
 *           1. prepareSignature — envia documentos + certificado ao SolidSign; recebe hashes + finalNonce.
 *           2. finalizeSignature — envia finalNonce + hashes assinados; recebe links para download.
 */

const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

class PdfPkcs1Service {
  constructor() {
    this.baseUrl = (process.env.SOLIDSIGN_API_BASE_URL || '').replace(/\/$/, '');
    this.authorization = process.env.SOLIDSIGN_API_AUTHORIZATION || '';
    this.profile = process.env.SOLIDSIGN_SIG_PROFILE || 'ADRB';
    this.hashAlgorithm = process.env.SOLIDSIGN_SIG_HASH_ALGORITHM || 'SHA256';
    this.sigFieldMeasurementUnit = process.env.SOLIDSIGN_SIG_FIELD_MEASUREMENT_UNIT || 'PIXELS';
    this.signatureFieldConfig = process.env.SOLIDSIGN_SIG_FIELD_CONFIG || '';
    this.reason = process.env.SOLIDSIGN_SIG_REASON || '';
    this.location = process.env.SOLIDSIGN_SIG_LOCATION || '';
    this.contact = process.env.SOLIDSIGN_SIG_CONTACT || '';
    this.signerCertPem = process.env.SOLIDSIGN_CERT_PEM || '';
    this.signatureImagePaths = (process.env.SOLIDSIGN_SIG_IMAGE_PATHS || '')
      .split(',').map(p => p.trim()).filter(Boolean);
  }

  // ─── Step 1: Prepare ──────────────────────────────────────────────────────

  async prepareSignature(documents) {
    console.info(`PDF PKCS1 prepare for ${documents.length} document(s).`);
    const prepUrl = `${this.baseUrl}/solidsign/dsig/pdf/pkcs1/sign-preparation`;
    const form = new FormData();

    for (let i = 0; i < documents.length; i++) {
      form.append(`document[${i}]`, documents[i].buffer, { filename: documents[i].originalname });
    }
    for (let i = 0; i < this.signatureImagePaths.length; i++) {
      const img = this.signatureImagePaths[i];
      if (fs.existsSync(img)) {
        form.append(`signatureImage[${i}]`, fs.createReadStream(img), { filename: path.basename(img) });
      }
    }

    form.append('profile', this.profile);
    form.append('hashAlgorithm', this.hashAlgorithm);
    form.append('sigFieldMeasurementUnit', this.sigFieldMeasurementUnit);
    appendIndexedJson(form, 'signatureFieldConfig', this.signatureFieldConfig);
    form.append('reason', this.reason);
    form.append('location', this.location);
    form.append('contact', this.contact);
    form.append('certificate', this.signerCertPem);

    // [EN]    Optional parameters — uncomment to use
    // [PT-BR] Parâmetros opcionais — descomente para usar
    // form.append('signatureFieldName',     'SignatureField1');
    // appendIndexedJson(form, 'signatureTextConfig', '[{"pageNumber":1,"coordinateX":200,"coordinateY":460,"text":"Signed","fontSize":10,"textColor":"BLACK"}]');
    // form.append('mdpPermissionLevel',     '1');
    // form.append('passwordsForDecryption', '["password"]');
    // form.append('documentInfoMetadata',   '{"title":"My Doc"}');
    // appendIndexedJson(form, 'signatureQrCodeConfig', '[...]');

    try {
      const resp = await axios.post(prepUrl, form, {
        headers: { Authorization: this.authorization, ...form.getHeaders() },
        timeout: 120000,
      });
      console.info(`PDF PKCS1 preparation OK. finalNonce=${resp.data.finalNonce}`);
      return resp.data;
    } catch (err) {
      this._logError('PDF PKCS1 preparation', err);
      return null;
    }
  }

  // ─── Step 2: Finalize ─────────────────────────────────────────────────────

  async finalizeSignature(allParams) {
    console.info('PDF PKCS1 finalize.');
    const finalUrl = `${this.baseUrl}/solidsign/dsig/pdf/pkcs1/sign-finalization`;
    const form = new FormData();
    for (const [key, value] of Object.entries(allParams)) {
      form.append(key, value);
    }

    try {
      const resp = await axios.post(finalUrl, form, {
        headers: { Authorization: this.authorization, ...form.getHeaders() },
        timeout: 120000,
      });
      console.info(`PDF PKCS1 finalization OK. identifier=${resp.data.identifier}`);
      return resp.data;
    } catch (err) {
      this._logError('PDF PKCS1 finalization', err);
      return null;
    }
  }

  // ─── Form endpoints (all params from caller) ──────────────────────────────

  async prepareForm({ authorization, baseUrl, certificate, documents, signatureImages = [],
    profile, hashAlgorithm, policyVersion, sigFieldMeasurementUnit, signatureFieldConfig,
    reason, location, contact, signatureFieldName, signatureTextConfig,
    mdpPermissionLevel, passwordsForDecryption, documentInfoMetadata, signatureQrCodeConfig }) {

    const prepUrl = `${baseUrl.replace(/\/$/, '')}/solidsign/dsig/pdf/pkcs1/sign-preparation`;
    const form = new FormData();

    for (let i = 0; i < documents.length; i++) {
      form.append(`document[${i}]`, documents[i].buffer, { filename: documents[i].originalname });
    }
    for (let i = 0; i < signatureImages.length; i++) {
      form.append(`signatureImage[${i}]`, signatureImages[i].buffer, { filename: signatureImages[i].originalname });
    }

    form.append('certificate', certificate);
    if (profile)                  form.append('profile', profile);
    if (hashAlgorithm)            form.append('hashAlgorithm', hashAlgorithm);
    if (policyVersion)            form.append('policyVersion', policyVersion);
    if (sigFieldMeasurementUnit)  form.append('sigFieldMeasurementUnit', sigFieldMeasurementUnit);
    if (signatureFieldConfig)     appendIndexedJson(form, 'signatureFieldConfig', signatureFieldConfig);
    if (reason)                   form.append('reason', reason);
    if (location)                 form.append('location', location);
    if (contact)                  form.append('contact', contact);
    if (signatureFieldName)       form.append('signatureFieldName', signatureFieldName);
    if (signatureTextConfig)      appendIndexedJson(form, 'signatureTextConfig', signatureTextConfig);
    if (mdpPermissionLevel)       form.append('mdpPermissionLevel', mdpPermissionLevel);
    if (passwordsForDecryption)   form.append('passwordsForDecryption', passwordsForDecryption);
    if (documentInfoMetadata)     form.append('documentInfoMetadata', documentInfoMetadata);
    if (signatureQrCodeConfig)    appendIndexedJson(form, 'signatureQrCodeConfig', signatureQrCodeConfig);

    try {
      const resp = await axios.post(prepUrl, form, {
        headers: { Authorization: authorization, ...form.getHeaders() },
        timeout: 120000,
      });
      console.info(`PDF PKCS1 form preparation OK. finalNonce=${resp.data.finalNonce}`);
      return resp.data;
    } catch (err) {
      this._logError('PDF PKCS1 form preparation', err);
      return null;
    }
  }

  async finalizeForm(authorization, baseUrl, allParams) {
    const finalUrl = `${baseUrl.replace(/\/$/, '')}/solidsign/dsig/pdf/pkcs1/sign-finalization`;
    const form = new FormData();
    for (const [key, value] of Object.entries(allParams)) {
      form.append(key, value);
    }

    try {
      const resp = await axios.post(finalUrl, form, {
        headers: { Authorization: authorization, ...form.getHeaders() },
        timeout: 120000,
      });
      console.info('PDF PKCS1 form finalization OK.');
      return resp.data;
    } catch (err) {
      this._logError('PDF PKCS1 form finalization', err);
      return null;
    }
  }

  _logError(context, err) {
    if (err.response) {
      console.error(`SolidSign API error ${err.response.status} during ${context}: ${JSON.stringify(err.response.data)}`);
    } else {
      console.error(`Unexpected error during ${context}: ${err.message}`);
    }
  }
}

// [EN]    Sends a visual-signature config as INDEXED fields: key[0], key[1], ...
//         The SolidSign API expects signatureFieldConfig[0]={...} per document,
//         NOT a single signatureFieldConfig=[{...}] — otherwise the field is ignored
//         and the visual stamp never appears.
// [PT-BR] Envia a config de assinatura visual como campos INDEXADOS: key[0], key[1], ...
//         A API espera signatureFieldConfig[0]={...} por documento, e NÃO um único
//         signatureFieldConfig=[{...}] — senão o campo é ignorado e o carimbo não aparece.
function appendIndexedJson(form, key, raw) {
  if (raw === undefined || raw === null || raw === '') return
  let parsed
  try { parsed = JSON.parse(raw) } catch (e) { form.append(`${key}[0]`, String(raw)); return }
  const items = Array.isArray(parsed) ? parsed : [parsed]
  items.forEach((it, i) => form.append(`${key}[${i}]`, typeof it === 'string' ? it : JSON.stringify(it)))
}

module.exports = PdfPkcs1Service;
