'use strict';
const { Sequelize } = require('sequelize');

const sequelize = process.env.DATABASE_URL
  ? new Sequelize(process.env.DATABASE_URL, {
      dialect: 'postgres',
      logging: false,
      pool: { max: 10, min: 2 },
      define: { underscored: true, timestamps: true, paranoid: true }
    })
  : new Sequelize('ipssi_db', 'ipssi_user', process.env.DB_PASSWORD, {
      host: process.env.DB_HOST || 'localhost',
      dialect: 'postgres',
      logging: false
    });

module.exports = sequelize;
