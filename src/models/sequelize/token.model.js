const { Model } = require('sequelize');
const { tokenTypes } = require('../../config/tokens');

module.exports = (sequelize, DataTypes) => {
  class Token extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
      Token.belongsTo(models.User, {
        as: 'userId',
        foreignKey: 'user',
      });
    }
  }

  Token.init(
    {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: DataTypes.INTEGER,
      },
      token: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      user: {
        type: DataTypes.INTEGER,
        allowNull: false,
        references: {
          model: 'User',
        },
      },
      type: {
        type: DataTypes.ENUM,
        allowNull: false,
        values: [tokenTypes.REFRESH, tokenTypes.RESET_PASSWORD, tokenTypes.VERIFY_EMAIL],
      },
      expires: {
        type: DataTypes.DATE,
        allowNull: false,
      },
      blacklisted: {
        type: DataTypes.BOOLEAN,
        default: false,
      },
      createdAt: {
        allowNull: false,
        type: DataTypes.DATE,
      },
      updatedAt: {
        allowNull: false,
        type: DataTypes.DATE,
      },
    },
    {
      sequelize,
      modelName: 'Token',
      tableName: 'Token',
      timestamps: true,
    }
  );
  return Token;
};
