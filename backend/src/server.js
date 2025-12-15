'use strict';
require('dotenv').config();
const app = require('./app');
const logger = require('./config/logger');
const sequelize = require('./config/database');

const PORT = process.env.PORT || 8000;

async function startServer() {
  try {
    await sequelize.authenticate();
    logger.info('✅ PostgreSQL connecté');
    
    if (process.env.NODE_ENV === 'development') {
      await sequelize.sync({ alter: true });
    }
    
    const server = app.listen(PORT, () => {
      logger.info(`✅ Serveur démarré sur le port ${PORT}`);
      logger.info(`🔐 Mode: ${process.env.NODE_ENV || 'development'}`);
    });
    
    const gracefulShutdown = async (signal) => {
      logger.info(`${signal} reçu. Arrêt...`);
      server.close(async () => {
        await sequelize.close();
        process.exit(0);
      });
    };
    
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
  } catch (error) {
    logger.error('Erreur démarrage:', error);
    process.exit(1);
  }
}

startServer();
