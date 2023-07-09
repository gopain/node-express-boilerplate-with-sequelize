const { Model, Op } = require('sequelize');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const { roles } = require('../../config/roles');

module.exports = (sequelize, DataTypes) => {
  class User extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
      User.hasMany(models.Token, {
        foreignKey: 'user',
      });
    }

    /**
     * Check if email is taken
     * @param {string} email - The user's email
     * @param {ObjectId} [excludeUserId] - The id of the user to be excluded
     * @returns {Promise<boolean>}
     */
    static async isEmailTaken(email, excludeUserId) {
      const user = await this.findOne({
        where: {
          email,
          id: {
            [Op.ne]: excludeUserId,
          },
        },
      });
      return !!user;
    }

    /**
     * Check if password matches the user's password
     * @param {string} password
     * @returns {Promise<boolean>}
     */
    async isPasswordMatch(password) {
      const user = this;
      return bcrypt.compare(password, user.password);
    }

    /**
     * @typedef {Object} QueryResult
     * @property {Document[]} results - Results found
     * @property {number} page - Current page
     * @property {number} limit - Maximum number of results per page
     * @property {number} totalPages - Total number of pages
     * @property {number} totalResults - Total number of documents
     */
    /**
     * Query for documents with pagination
     * @param {Object} [filter] - Mongo filter
     * @param {Object} [options] - Query options
     * @param {string} [options.sortBy] - Sorting criteria using the format: sortField:(desc|asc). Multiple sorting criteria should be separated by commas (,)
     * @param {string} [options.populate] - Populate data fields. Hierarchy of fields should be separated by (.). Multiple populating criteria should be separated by commas (,)
     * @param {number} [options.limit] - Maximum number of results per page (default = 10)
     * @param {number} [options.page] - Current page (default = 1)
     * @returns {Promise<QueryResult>}
     */
    static async paginate(filter, options) {
      let sortBy = null;
      if (options.sortBy) {
        const sortingCriteria = [];
        options.sortBy.split(',').forEach((sortOption) => {
          const [key, order] = sortOption.split(':');
          console.log({ key, order });
          sortingCriteria.push([key, order.toUpperCase()]);
        });
        sortBy = sortingCriteria;
      } else {
        sortBy = [['createdAt']];
      }

      const limit = options.limit && parseInt(options.limit, 10) > 0 ? parseInt(options.limit, 10) : 10;
      const page = options.page && parseInt(options.page, 10) > 0 ? parseInt(options.page, 10) : 1;
      const offset = (page - 1) * limit;
      console.log(JSON.stringify({ filter, limit, page, offset, order: sortBy }));

      let res;
      if (Object.keys(filter).length !== 0) {
        if (filter.name && !filter.role) {
          res = await User.findAndCountAll({
            where: {
              name: filter.name,
            },
            limit,
            offset,
            order: sortBy,
          });
        } else if (!filter.name && filter.role) {
          res = await User.findAndCountAll({
            where: {
              role: filter.role,
            },
            limit,
            offset,
            order: sortBy,
          });
        } else if (filter.name && filter.role) {
          res = await User.findAndCountAll({
            where: {
              name: filter.name,
              role: filter.role,
            },
            limit,
            offset,
            order: sortBy,
          });
        }
      } else {
        res = await User.findAndCountAll({
          limit,
          offset,
          order: sortBy,
        });
      }
      const results = res ? [...res.rows] : [];
      const totalResults = res ? res.count : 0;
      const totalPages = Math.ceil(res ? res.count / limit : 0);
      const result = {
        limit,
        page,
        results,
        totalResults,
        totalPages,
      };
      console.log(result);
      return result;
    }

    /**
     * override the default toJSON method, no to output fields password, createdAt, updatedAt, deleteAt
     * @returns {User}
     */
    toJSON() {
      let user = { ...this.get() };
      delete user.password;
      delete user.createdAt;
      delete user.updatedAt;
      delete user.deletedAt;
      return user;
    }
  }

  User.init(
    {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: DataTypes.INTEGER,
      },
      name: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate: {
          validate(value) {
            if (!validator.isEmail(value)) {
              throw new Error('Invalid email');
            }
          },
        },
      },
      password: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
          len: [8], // minimum length 8
          validate(value) {
            if (!value.match(/\d/) || !value.match(/[a-zA-Z]/)) {
              throw new Error('Password must contain at least one letter and one number');
            }
          },
        },
      },
      role: {
        type: DataTypes.ENUM,
        allowNull: false,
        values: roles,
        defaultValue: 'user',
        validate: {
          validate(value) {
            if (!roles.includes(value)) {
              throw new Error('Invalid role');
            }
          },
        },
      },
      isEmailVerified: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      createdAt: {
        allowNull: false,
        type: DataTypes.DATE,
      },
      updatedAt: {
        allowNull: false,
        type: DataTypes.DATE,
      },
      deletedAt: {
        allowNull: true,
        type: DataTypes.DATE,
      },
    },
    {
      // 默认作用域脱敏password字段
      defaultScope: {
        attributes: {
          exclude: ['password'],
        },
      },
      scopes: {
        // 仅当需要password字段时，使用作用域includePassword
        includePassword: {
          attributes: {
            include: ['password'],
          },
        },
      },
      sequelize,
      modelName: 'User',
      tableName: 'User',
      timestamps: true,
      paranoid: true,
    }
  );

  // 保存前钩子
  User.addHook('beforeSave', 'beforeSaveHook', async (user, options) => {
    if (user.changed('password')) {
      user.password = await bcrypt.hash(user.password, 8);
      console.log('changing user password');
    }
  });

  return User;
};
