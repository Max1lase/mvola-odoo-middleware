const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration MVola
const MVOLA_CONFIG = {
  sandbox: {
    baseUrl: 'https://devapi.mvola.mg',
    tokenUrl: 'https://devapi.mvola.mg/token'
  },
  production: {
    baseUrl: 'https://api.mvola.mg',
    tokenUrl: 'https://api.mvola.mg/token'
  }
};

// Middleware de sécurité
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limite à 100 requêtes par IP
  message: 'Trop de requêtes, réessayez plus tard'
});
app.use(limiter);

// Logging
app.use(morgan('combined'));

// Parser JSON
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Variables globales pour cache token
let tokenCache = {
  token: null,
  expiresAt: null
};

// =================== FONCTIONS UTILITAIRES ===================

// Générer l'en-tête Authorization pour MVola
function generateAuthHeader() {
  const consumerKey = process.env.MVOLA_CONSUMER_KEY;
  const consumerSecret = process.env.MVOLA_CONSUMER_SECRET;
  
  if (!consumerKey || !consumerSecret) {
    throw new Error('Clés MVola manquantes dans les variables d\'environnement');
  }
  
  const credentials = Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64');
  return `Basic ${credentials}`;
}

// Vérifier si le token est encore valide
function isTokenValid() {
  return tokenCache.token && tokenCache.expiresAt && Date.now() < tokenCache.expiresAt;
}

// Obtenir un token MVola (avec cache)
async function getMvolaToken() {
  // Retourner le token en cache s'il est valide
  if (isTokenValid()) {
    return tokenCache.token;
  }

  try {
    const config = process.env.NODE_ENV === 'production' 
      ? MVOLA_CONFIG.production 
      : MVOLA_CONFIG.sandbox;

    const response = await axios.post(config.tokenUrl, 
      'grant_type=client_credentials&scope=EXT_INT_MVOLA_SCOPE',
      {
        headers: {
          'Authorization': generateAuthHeader(),
          'Content-Type': 'application/x-www-form-urlencoded',
          'Cache-Control': 'no-cache'
        }
      }
    );

    const { access_token, expires_in } = response.data;
    
    // Mettre en cache avec une marge de sécurité de 5 minutes
    tokenCache = {
      token: access_token,
      expiresAt: Date.now() + (expires_in - 300) * 1000
    };

    return access_token;
  } catch (error) {
    console.error('Erreur génération token MVola:', error.response?.data || error.message);
    throw new Error('Impossible d\'obtenir le token MVola');
  }
}

// =================== ROUTES API ===================

// Route de santé
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Route d'information
app.get('/', (req, res) => {
  res.json({
    service: 'MVola Middleware API',
    version: '1.0.0',
    endpoints: {
      health: 'GET /health',
      authenticate: 'POST /mvola/auth',
      initiate: 'POST /mvola/transaction/initiate',
      status: 'GET /mvola/transaction/status/:correlationId',
      details: 'GET /mvola/transaction/details/:transactionId'
    }
  });
});

// 1. Authentification MVola
app.post('/mvola/auth', async (req, res) => {
  try {
    const token = await getMvolaToken();
    res.json({
      success: true,
      message: 'Token généré avec succès',
      data: {
        hasToken: !!token,
        expiresAt: tokenCache.expiresAt
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
      error: 'AUTH_ERROR'
    });
  }
});

// 2. Initier une transaction
app.post('/mvola/transaction/initiate', async (req, res) => {
  try {
    const token = await getMvolaToken();
    const config = process.env.NODE_ENV === 'production' 
      ? MVOLA_CONFIG.production 
      : MVOLA_CONFIG.sandbox;

    const {
      amount,
      currency = 'Ar',
      descriptionText,
      customerMSISDN,
      partnerMSISDN,
      partnerName,
      correlationId,
      callbackUrl
    } = req.body;

    // Validation des données requises
    if (!amount || !customerMSISDN || !partnerMSISDN) {
      return res.status(400).json({
        success: false,
        message: 'Paramètres manquants: amount, customerMSISDN, partnerMSISDN requis'
      });
    }

    const transactionData = {
      amount: amount.toString(),
      currency,
      descriptionText: descriptionText || 'Paiement Odoo',
      requestDate: new Date().toISOString(),
      debitParty: [{ key: 'msisdn', value: customerMSISDN }],
      creditParty: [{ key: 'msisdn', value: partnerMSISDN }],
      metadata: [
        { key: 'partnerName', value: partnerName || 'Odoo Store' }
      ],
      requestingOrganisationTransactionReference: correlationId || `ODO-${Date.now()}`
    };

    const headers = {
      'Authorization': `Bearer ${token}`,
      'Version': '1.0',
      'X-CorrelationID': correlationId || `cor-${Date.now()}`,
      'UserLanguage': 'fr',
      'UserAccountIdentifier': `msisdn;${partnerMSISDN}`,
      'partnerName': partnerName || 'Odoo Store',
      'Content-Type': 'application/json',
      'Cache-Control': 'no-cache'
    };

    if (callbackUrl) {
      headers['X-Callback-URL'] = callbackUrl;
    }

    const response = await axios.post(
      `${config.baseUrl}/mvola/mm/transactions/type/merchantpay/1.0.0/`,
      transactionData,
      { headers }
    );

    res.json({
      success: true,
      message: 'Transaction initiée avec succès',
      data: response.data
    });

  } catch (error) {
    console.error('Erreur initiation transaction:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      message: 'Erreur lors de l\'initiation de la transaction',
      error: error.response?.data || error.message
    });
  }
});

// 3. Vérifier le statut d'une transaction
app.get('/mvola/transaction/status/:correlationId', async (req, res) => {
  try {
    const token = await getMvolaToken();
    const { correlationId } = req.params;
    const config = process.env.NODE_ENV === 'production' 
      ? MVOLA_CONFIG.production 
      : MVOLA_CONFIG.sandbox;

    const response = await axios.get(
      `${config.baseUrl}/mvola/mm/transactions/type/merchantpay/1.0.0/status/${correlationId}`,
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Version': '1.0',
          'X-CorrelationID': `check-${Date.now()}`,
          'UserLanguage': 'fr',
          'UserAccountIdentifier': `msisdn;${process.env.MVOLA_PARTNER_MSISDN}`,
          'partnerName': process.env.MVOLA_PARTNER_NAME || 'Odoo Store',
          'Cache-Control': 'no-cache'
        }
      }
    );

    res.json({
      success: true,
      data: response.data
    });

  } catch (error) {
    console.error('Erreur vérification statut:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      message: 'Erreur lors de la vérification du statut',
      error: error.response?.data || error.message
    });
  }
});

// 4. Obtenir les détails d'une transaction
app.get('/mvola/transaction/details/:transactionId', async (req, res) => {
  try {
    const token = await getMvolaToken();
    const { transactionId } = req.params;
    const config = process.env.NODE_ENV === 'production' 
      ? MVOLA_CONFIG.production 
      : MVOLA_CONFIG.sandbox;

    const response = await axios.get(
      `${config.baseUrl}/mvola/mm/transactions/type/merchantpay/1.0.0/${transactionId}`,
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Version': '1.0',
          'X-CorrelationID': `details-${Date.now()}`,
          'UserLanguage': 'fr',
          'UserAccountIdentifier': `msisdn;${process.env.MVOLA_PARTNER_MSISDN}`,
          'partnerName': process.env.MVOLA_PARTNER_NAME || 'Odoo Store',
          'Cache-Control': 'no-cache'
        }
      }
    );

    res.json({
      success: true,
      data: response.data
    });

  } catch (error) {
    console.error('Erreur récupération détails:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      message: 'Erreur lors de la récupération des détails',
      error: error.response?.data || error.message
    });
  }
});

// 5. Endpoint pour recevoir les callbacks MVola
app.put('/mvola/callback/:correlationId?', (req, res) => {
  try {
    console.log('Callback MVola reçu:', {
      params: req.params,
      body: req.body,
      timestamp: new Date().toISOString()
    });

    // Ici tu peux ajouter la logique pour notifier Odoo
    // ou mettre à jour la base de données

    res.json({
      success: true,
      message: 'Callback traité avec succès'
    });

  } catch (error) {
    console.error('Erreur traitement callback:', error);
    res.status(500).json({
      success: false,
      message: 'Erreur lors du traitement du callback'
    });
  }
});

// Middleware de gestion d'erreurs
app.use((error, req, res, next) => {
  console.error('Erreur serveur:', error);
  res.status(500).json({
    success: false,
    message: 'Erreur interne du serveur',
    error: process.env.NODE_ENV === 'development' ? error.message : 'Internal Server Error'
  });
});

// Route 404
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint non trouvé',
    availableEndpoints: [
      'GET /',
      'GET /health',
      'POST /mvola/auth',
      'POST /mvola/transaction/initiate',
      'GET /mvola/transaction/status/:correlationId',
      'GET /mvola/transaction/details/:transactionId',
      'PUT /mvola/callback/:correlationId?'
    ]
  });
});

// Démarrage du serveur
app.listen(PORT, () => {
  console.log(`🚀 Serveur MVola middleware démarré sur le port ${PORT}`);
  console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 URL: http://localhost:${PORT}`);
});

module.exports = app;
