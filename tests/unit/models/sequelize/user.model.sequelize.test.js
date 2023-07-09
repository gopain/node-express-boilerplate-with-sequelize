const faker = require('faker');
const { User } = require('../../../../src/models/sequelize');
const setupTestDB = require('../../../utils/setupTestDB.sequelize');

setupTestDB();

describe('User model', () => {
  describe('User validation', () => {
    let newUser;
    beforeEach(() => {
      newUser = {
        name: faker.name.findName(),
        email: faker.internet.email().toLowerCase(),
        password: 'password1',
        role: 'user',
      };
    });

    test('should correctly validate a valid user', async () => {
      await expect(User.create(newUser)).resolves.toBeInstanceOf(User);
    });

    test('should throw a validation error if email is invalid', async () => {
      newUser.email = 'invalidEmail';
      await expect(User.create(newUser)).rejects.toThrow();
    });

    test('should throw a validation error if password length is less than 8 characters', async () => {
      newUser.password = 'passwo1';
      await expect(User.create(newUser)).rejects.toThrow();
    });

    test('should throw a validation error if password does not contain numbers', async () => {
      newUser.password = 'password';
      await expect(User.create(newUser)).rejects.toThrow();
    });

    test('should throw a validation error if password does not contain letters', async () => {
      newUser.password = '11111111';
      await expect(User.create(newUser)).rejects.toThrow();
    });

    test('should throw a validation error if role is unknown', async () => {
      newUser.role = 'invalid';
      await expect(User.create(newUser)).rejects.toThrow();
    });
  });

  describe('User toJSON()', () => {
    test('should not return user password when toJSON is called', async () => {
      const newUser = {
        name: faker.name.findName(),
        email: faker.internet.email().toLowerCase(),
        password: 'password1',
        role: 'user',
      };
      const user = await User.create(newUser);
      expect(user.toJSON()).not.toHaveProperty('password');
    });
  });
});