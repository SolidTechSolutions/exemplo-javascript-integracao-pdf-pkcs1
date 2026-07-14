'use strict';

/**
 * [EN]    PAdES (PDF) two-step signing example using PKCS#1 (browser extension / external private key).
 *         Start: node src/index.js
 *
 *         Flow:
 *           Step 1 — POST /api/pdf/pkcs1/prepare    → returns hashes + finalNonce to the browser extension
 *           Step 2 — POST /api/pdf/pkcs1/finalize   → receives signed hashes + finalNonce, returns result
 *
 * [PT-BR] Exemplo de assinatura PAdES (PDF) em dois passos com PKCS#1 (extensão do browser).
 *         Iniciar: node src/index.js
 *
 *         Fluxo:
 *           Passo 1 — POST /api/pdf/pkcs1/prepare   → retorna hashes + finalNonce para a extensão do browser
 *           Passo 2 — POST /api/pdf/pkcs1/finalize  → recebe hashes assinados + finalNonce, retorna resultado
 */

require('dotenv').config();
const express = require('express');
const multer = require('multer');
const PdfPkcs1Service = require('./service');

const app = express();
app.use(express.urlencoded({ extended: true }));
const upload = multer({ storage: multer.memoryStorage() });
const service = new PdfPkcs1Service();

/**
 * [EN]    Step 1 — sends documents to SolidSign and returns hashes + finalNonce.
 *         Certificate PEM is read from .env (SOLIDSIGN_CERT_PEM).
 * [PT-BR] Passo 1 — envia documentos ao SolidSign e retorna hashes + finalNonce.
 *         O PEM do certificado é lido do .env (SOLIDSIGN_CERT_PEM).
 */
app.post('/api/pdf/pkcs1/prepare',
  upload.fields([{ name: 'document' }, { name: 'signatureImage' }]),
  async (req, res) => {
    const documents = req.files['document'] || [];
    const result = await service.prepareSignature(documents);
    if (result) return res.json(result);
    return res.status(500).json({ error: 'Preparation failed. Check logs.' });
  }
);

/**
 * [EN]    Step 2 — receives finalNonce and signatureValue[i] from the browser extension,
 *         forwards to SolidSign, and returns the signing result with download links.
 * [PT-BR] Passo 2 — recebe finalNonce e signatureValue[i] da extensão do browser,
 *         encaminha ao SolidSign e retorna o resultado com links para download.
 */
app.post('/api/pdf/pkcs1/finalize', async (req, res) => {
  const result = await service.finalizeSignature(req.body);
  if (result) return res.json(result);
  return res.status(500).json({ error: 'Finalization failed. Check logs.' });
});

// ─── Form endpoints (all params from request) ─────────────────────────────────

app.post('/api/pdf/pkcs1/prepare/form',
  upload.fields([{ name: 'document' }, { name: 'signatureImage' }]),
  async (req, res) => {
    const documents = req.files['document'] || [];
    const signatureImages = req.files['signatureImage'] || [];
    const { authorization, baseUrl, certificate, profile, hashAlgorithm, policyVersion,
            sigFieldMeasurementUnit, signatureFieldConfig, reason, location, contact,
            signatureFieldName, signatureTextConfig, mdpPermissionLevel,
            passwordsForDecryption, documentInfoMetadata, signatureQrCodeConfig } = req.body;

    const result = await service.prepareForm({
      authorization, baseUrl, certificate, documents, signatureImages,
      profile, hashAlgorithm, policyVersion, sigFieldMeasurementUnit,
      signatureFieldConfig, reason, location, contact, signatureFieldName,
      signatureTextConfig, mdpPermissionLevel, passwordsForDecryption,
      documentInfoMetadata, signatureQrCodeConfig,
    });
    if (result) return res.json(result);
    return res.status(500).json({ error: 'Preparation failed. Check logs.' });
  }
);

app.post('/api/pdf/pkcs1/finalize/form', async (req, res) => {
  const { authorization, baseUrl, ...rest } = req.body;
  const result = await service.finalizeForm(authorization, baseUrl, rest);
  if (result) return res.json(result);
  return res.status(500).json({ error: 'Finalization failed. Check logs.' });
});

const PORT = process.env.PORT || 8089;
app.listen(PORT, () => console.info(`SolidSign PDF PKCS1 example running on port ${PORT}`));
