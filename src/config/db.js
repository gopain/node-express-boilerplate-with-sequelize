// const log4js = require('log4js');

// const logger = log4js.getLogger('Sequelize');

module.exports = {
  development: {
    dialect: 'sqlite',
    storage: 'database/dev.sqlite',
    // logging: (msg) => logger.info(msg),
  },
  test: {
    dialect: 'sqlite',
    storage: 'database/test.sqlite',
    // logging: (msg) => logger.info(msg),
  },
  production: {
    dialect: 'sqlite',
    storage: 'database/prod.sqlite',
    // logging: (msg) => logger.info(msg),
  },
};
