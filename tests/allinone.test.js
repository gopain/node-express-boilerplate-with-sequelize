const request = require('supertest');
const faker = require('faker');
const httpStatus = require('http-status');
const httpMocks = require('node-mocks-http');
const moment = require('moment');
const bcrypt = require('bcryptjs');
const app = require('../src/app');
const config = require('../src/config/config');
const auth = require('../src/middlewares/auth');
const { userService, tokenService, emailService } = require('../src/services');
const ApiError = require('../src/utils/ApiError');
const { User, Token } = require('../src/models/sequelize');
const { roleRights } = require('../src/config/roles');
const { tokenTypes } = require('../src/config/tokens');
const { userOne, userTwo, admin, insertUsers } = require('./fixtures/sequelize/user.sequelize.fixture');
const { userOneAccessToken, adminAccessToken } = require('./fixtures/sequelize/token.sequelize.fixture');
const pick = require('../src/utils/pick');

beforeEach(async () => {
  await Promise.all([User.destroy({ truncate: true, force: true }), Token.destroy({ truncate: true, force: true })]);
});

describe('Auth routes', () => {
  describe('POST /v1/auth/register', () => {
    let newUser;
    beforeEach(() => {
      newUser = {
        name: faker.name.findName(),
        email: faker.internet.email().toLowerCase(),
        password: 'password1',
      };
    });

    test('should return 201 and successfully register user if request data is ok', async () => {
      const res = await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.CREATED);

      expect(res.body.user).not.toHaveProperty('password');
      expect(res.body.user).toEqual({
        id: expect.anything(),
        name: newUser.name,
        email: newUser.email,
        role: 'user',
        isEmailVerified: false,
      });

      const dbUser = await userService.getUserById(res.body.user.id);
      expect(dbUser).toBeDefined();
      expect(dbUser.password).not.toBe(newUser.password);
      expect(dbUser).toMatchObject({ name: newUser.name, email: newUser.email, role: 'user', isEmailVerified: false });

      expect(res.body.tokens).toEqual({
        access: { token: expect.anything(), expires: expect.anything() },
        refresh: { token: expect.anything(), expires: expect.anything() },
      });
    });

    test('should return 400 error if email is invalid', async () => {
      newUser.email = 'invalidEmail';

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if email is already used', async () => {
      await insertUsers([userOne]);
      newUser.email = userOne.email;

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if password length is less than 8 characters', async () => {
      newUser.password = 'passwo1';

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if password does not contain both letters and numbers', async () => {
      newUser.password = 'password';

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);

      newUser.password = '11111111';

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);
    });
  });

  describe('POST /v1/auth/login', () => {
    test('should return 200 and login user if email and password match', async () => {
      await insertUsers([userOne]);
      const loginCredentials = {
        email: userOne.email,
        password: userOne.password,
      };

      const res = await request(app).post('/v1/auth/login').send(loginCredentials).expect(httpStatus.OK);

      expect(res.body.user).toEqual({
        id: expect.anything(),
        name: userOne.name,
        email: userOne.email,
        role: userOne.role,
        isEmailVerified: userOne.isEmailVerified,
      });

      expect(res.body.tokens).toEqual({
        access: { token: expect.anything(), expires: expect.anything() },
        refresh: { token: expect.anything(), expires: expect.anything() },
      });
    });

    test('should return 401 error if there are no users with that email', async () => {
      const loginCredentials = {
        email: userOne.email,
        password: userOne.password,
      };

      const res = await request(app).post('/v1/auth/login').send(loginCredentials).expect(httpStatus.UNAUTHORIZED);

      expect(res.body).toEqual({ code: httpStatus.UNAUTHORIZED, message: 'Incorrect email or password' });
    });

    test('should return 401 error if password is wrong', async () => {
      await insertUsers([userOne]);
      const loginCredentials = {
        email: userOne.email,
        password: 'wrongPassword1',
      };

      const res = await request(app).post('/v1/auth/login').send(loginCredentials).expect(httpStatus.UNAUTHORIZED);

      expect(res.body).toEqual({ code: httpStatus.UNAUTHORIZED, message: 'Incorrect email or password' });
    });
  });

  describe('POST /v1/auth/logout', () => {
    test('should return 204 if refresh token is valid', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(userOne.id, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, userOne.id, expires, tokenTypes.REFRESH);

      await request(app).post('/v1/auth/logout').send({ refreshToken }).expect(httpStatus.NO_CONTENT);

      const dbRefreshTokenDoc = await Token.findOne({
        where: { token: refreshToken },
      });
      expect(dbRefreshTokenDoc).toBe(null);
    });

    test('should return 400 error if refresh token is missing from request body', async () => {
      await request(app).post('/v1/auth/logout').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 404 error if refresh token is not found in the database', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(userOne.id, expires, tokenTypes.REFRESH);

      await request(app).post('/v1/auth/logout').send({ refreshToken }).expect(httpStatus.NOT_FOUND);
    });

    test('should return 404 error if refresh token is blacklisted', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(userOne.id, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, userOne.id, expires, tokenTypes.REFRESH, true);

      await request(app).post('/v1/auth/logout').send({ refreshToken }).expect(httpStatus.NOT_FOUND);
    });
  });

  describe('POST /v1/auth/refresh-tokens', () => {
    test('should return 200 and new auth tokens if refresh token is valid', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(userOne.id, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, userOne.id, expires, tokenTypes.REFRESH);

      const res = await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.OK);

      expect(res.body).toEqual({
        access: { token: expect.anything(), expires: expect.anything() },
        refresh: { token: expect.anything(), expires: expect.anything() },
      });

      const dbRefreshTokenDoc = await Token.findOne({
        where: {
          token: res.body.refresh.token,
        },
      });
      expect(dbRefreshTokenDoc).toMatchObject({ type: tokenTypes.REFRESH, user: userOne.id, blacklisted: false });

      const dbRefreshTokenCount = await Token.count();
      expect(dbRefreshTokenCount).toBe(1);
    });

    test('should return 400 error if refresh token is missing from request body', async () => {
      await request(app).post('/v1/auth/refresh-tokens').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 401 error if refresh token is signed using an invalid secret', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(userOne.id, expires, tokenTypes.REFRESH, 'invalidSecret');
      await tokenService.saveToken(refreshToken, userOne.id, expires, tokenTypes.REFRESH);

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if refresh token is not found in the database', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(userOne.id, expires, tokenTypes.REFRESH);

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if refresh token is blacklisted', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(userOne.id, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, userOne.id, expires, tokenTypes.REFRESH, true);

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if refresh token is expired', async () => {
      await insertUsers([userOne]);
      const expires = moment().subtract(1, 'minutes');
      const refreshToken = tokenService.generateToken(userOne.id, expires);
      await tokenService.saveToken(refreshToken, userOne.id, expires, tokenTypes.REFRESH);

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if user is not found', async () => {
      await insertUsers([userTwo]); // insert userTwo first to avoid SequelizeForeignKeyConstraintError: SQLITE_CONSTRAINT: FOREIGN KEY constraint failed
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(userOne.id, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, userTwo.id, expires, tokenTypes.REFRESH);

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });
  });

  describe('POST /v1/auth/forgot-password', () => {
    beforeEach(() => {
      jest.spyOn(emailService.transport, 'sendMail').mockResolvedValue();
    });

    test('should return 204 and send reset password email to the user', async () => {
      await insertUsers([userOne]);
      const sendResetPasswordEmailSpy = jest.spyOn(emailService, 'sendResetPasswordEmail');

      await request(app).post('/v1/auth/forgot-password').send({ email: userOne.email }).expect(httpStatus.NO_CONTENT);

      expect(sendResetPasswordEmailSpy).toHaveBeenCalledWith(userOne.email, expect.any(String));
      const resetPasswordToken = sendResetPasswordEmailSpy.mock.calls[0][1];
      const dbResetPasswordTokenDoc = await Token.findOne({
        where: {
          token: resetPasswordToken,
          user: userOne.id,
        },
      });
      expect(dbResetPasswordTokenDoc).toBeDefined();
    });

    test('should return 400 if email is missing', async () => {
      await insertUsers([userOne]);

      await request(app).post('/v1/auth/forgot-password').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 404 if email does not belong to any user', async () => {
      await request(app).post('/v1/auth/forgot-password').send({ email: userOne.email }).expect(httpStatus.NOT_FOUND);
    });
  });

  describe('POST /v1/auth/reset-password', () => {
    test('should return 204 and reset the password', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken(userOne.id, expires, tokenTypes.RESET_PASSWORD);
      await tokenService.saveToken(resetPasswordToken, userOne.id, expires, tokenTypes.RESET_PASSWORD);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.NO_CONTENT);

      const dbUser = await userService.getUserByEmailWithPassword(userOne.email);
      const isPasswordMatch = await bcrypt.compare('password2', dbUser.password);
      expect(isPasswordMatch).toBe(true);

      const dbResetPasswordTokenCount = await Token.count({
        where: {
          user: userOne.id,
          type: tokenTypes.RESET_PASSWORD,
        },
      });
      expect(dbResetPasswordTokenCount).toBe(0);
    });

    test('should return 400 if reset password token is missing', async () => {
      await insertUsers([userOne]);

      await request(app).post('/v1/auth/reset-password').send({ password: 'password2' }).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 401 if reset password token is blacklisted', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken(userOne.id, expires, tokenTypes.RESET_PASSWORD);
      await tokenService.saveToken(resetPasswordToken, userOne.id, expires, tokenTypes.RESET_PASSWORD, true);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 if reset password token is expired', async () => {
      await insertUsers([userOne]);
      const expires = moment().subtract(1, 'minutes');
      const resetPasswordToken = tokenService.generateToken(userOne.id, expires, tokenTypes.RESET_PASSWORD);
      await tokenService.saveToken(resetPasswordToken, userOne.id, expires, tokenTypes.RESET_PASSWORD);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 if user is not found', async () => {
      await insertUsers([userTwo]); // insert userTwo first to avoid SequelizeForeignKeyConstraintError: SQLITE_CONSTRAINT: FOREIGN KEY constraint failed
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken(userOne.id, expires, tokenTypes.RESET_PASSWORD);
      await tokenService.saveToken(resetPasswordToken, userTwo.id, expires, tokenTypes.RESET_PASSWORD);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 400 if password is missing or invalid', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken(userOne.id, expires, tokenTypes.RESET_PASSWORD);
      await tokenService.saveToken(resetPasswordToken, userOne.id, expires, tokenTypes.RESET_PASSWORD);

      await request(app).post('/v1/auth/reset-password').query({ token: resetPasswordToken }).expect(httpStatus.BAD_REQUEST);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'short1' })
        .expect(httpStatus.BAD_REQUEST);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password' })
        .expect(httpStatus.BAD_REQUEST);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: '11111111' })
        .expect(httpStatus.BAD_REQUEST);
    });
  });

  describe('POST /v1/auth/send-verification-email', () => {
    beforeEach(() => {
      jest.spyOn(emailService.transport, 'sendMail').mockResolvedValue();
    });

    test('should return 204 and send verification email to the user', async () => {
      await insertUsers([userOne]);
      const sendVerificationEmailSpy = jest.spyOn(emailService, 'sendVerificationEmail');

      await request(app)
        .post('/v1/auth/send-verification-email')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.NO_CONTENT);

      expect(sendVerificationEmailSpy).toHaveBeenCalledWith(userOne.email, expect.any(String));
      const verifyEmailToken = sendVerificationEmailSpy.mock.calls[0][1];
      const dbVerifyEmailToken = await Token.findOne({
        where: {
          token: verifyEmailToken,
          user: userOne.id,
        },
      });

      expect(dbVerifyEmailToken).toBeDefined();
    });

    test('should return 401 error if access token is missing', async () => {
      await insertUsers([userOne]);

      await request(app).post('/v1/auth/send-verification-email').send().expect(httpStatus.UNAUTHORIZED);
    });
  });

  describe('POST /v1/auth/verify-email', () => {
    test('should return 204 and verify the email', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.verifyEmailExpirationMinutes, 'minutes');
      const verifyEmailToken = tokenService.generateToken(userOne.id, expires);
      await tokenService.saveToken(verifyEmailToken, userOne.id, expires, tokenTypes.VERIFY_EMAIL);

      await request(app)
        .post('/v1/auth/verify-email')
        .query({ token: verifyEmailToken })
        .send()
        .expect(httpStatus.NO_CONTENT);

      const dbUser = await userService.getUserById(userOne.id);

      expect(dbUser.isEmailVerified).toBe(true);

      const dbVerifyEmailToken = await Token.count({
        where: {
          user: userOne.id,
          type: tokenTypes.VERIFY_EMAIL,
        },
      });
      expect(dbVerifyEmailToken).toBe(0);
    });

    test('should return 400 if verify email token is missing', async () => {
      await insertUsers([userOne]);

      await request(app).post('/v1/auth/verify-email').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 401 if verify email token is blacklisted', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.verifyEmailExpirationMinutes, 'minutes');
      const verifyEmailToken = tokenService.generateToken(userOne.id, expires);
      await tokenService.saveToken(verifyEmailToken, userOne.id, expires, tokenTypes.VERIFY_EMAIL, true);

      await request(app)
        .post('/v1/auth/verify-email')
        .query({ token: verifyEmailToken })
        .send()
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 if verify email token is expired', async () => {
      await insertUsers([userOne]);
      const expires = moment().subtract(1, 'minutes');
      const verifyEmailToken = tokenService.generateToken(userOne.id, expires);
      await tokenService.saveToken(verifyEmailToken, userOne.id, expires, tokenTypes.VERIFY_EMAIL);

      await request(app)
        .post('/v1/auth/verify-email')
        .query({ token: verifyEmailToken })
        .send()
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 if user is not found', async () => {
      await insertUsers([userTwo]); // insert userTwo first to avoid SequelizeForeignKeyConstraintError: SQLITE_CONSTRAINT: FOREIGN KEY constraint failed
      const expires = moment().add(config.jwt.verifyEmailExpirationMinutes, 'minutes');
      const verifyEmailToken = tokenService.generateToken(userOne.id, expires);
      await tokenService.saveToken(verifyEmailToken, userTwo.id, expires, tokenTypes.VERIFY_EMAIL);

      await request(app)
        .post('/v1/auth/verify-email')
        .query({ token: verifyEmailToken })
        .send()
        .expect(httpStatus.UNAUTHORIZED);
    });
  });
});

describe('Auth middleware', () => {
  test('should call next with no errors if access token is valid', async () => {
    await insertUsers([userOne]);
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${userOneAccessToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith();
    expect(req.user.id).toEqual(userOne.id);
  });

  test('should call next with unauthorized error if access token is not found in header', async () => {
    await insertUsers([userOne]);
    const req = httpMocks.createRequest();
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: httpStatus.UNAUTHORIZED, message: 'Please authenticate' })
    );
  });

  test('should call next with unauthorized error if access token is not a valid jwt token', async () => {
    await insertUsers([userOne]);
    const req = httpMocks.createRequest({ headers: { Authorization: 'Bearer randomToken' } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: httpStatus.UNAUTHORIZED, message: 'Please authenticate' })
    );
  });

  test('should call next with unauthorized error if the token is not an access token', async () => {
    await insertUsers([userOne]);
    const expires = moment().add(config.jwt.accessExpirationMinutes, 'minutes');
    const refreshToken = tokenService.generateToken(userOne.id, expires, tokenTypes.REFRESH);
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${refreshToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: httpStatus.UNAUTHORIZED, message: 'Please authenticate' })
    );
  });

  test('should call next with unauthorized error if access token is generated with an invalid secret', async () => {
    await insertUsers([userOne]);
    const expires = moment().add(config.jwt.accessExpirationMinutes, 'minutes');
    const accessToken = tokenService.generateToken(userOne.id, expires, tokenTypes.ACCESS, 'invalidSecret');
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${accessToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: httpStatus.UNAUTHORIZED, message: 'Please authenticate' })
    );
  });

  test('should call next with unauthorized error if access token is expired', async () => {
    await insertUsers([userOne]);
    const expires = moment().subtract(1, 'minutes');
    const accessToken = tokenService.generateToken(userOne.id, expires, tokenTypes.ACCESS);
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${accessToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: httpStatus.UNAUTHORIZED, message: 'Please authenticate' })
    );
  });

  test('should call next with unauthorized error if user is not found', async () => {
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${userOneAccessToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: httpStatus.UNAUTHORIZED, message: 'Please authenticate' })
    );
  });

  test('should call next with forbidden error if user does not have required rights and userId is not in params', async () => {
    await insertUsers([userOne]);
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${userOneAccessToken}` } });
    const next = jest.fn();

    await auth('anyRight')(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: httpStatus.FORBIDDEN, message: 'Forbidden' }));
  });

  test('should call next with no errors if user does not have required rights but userId is in params', async () => {
    await insertUsers([userOne]);
    const req = httpMocks.createRequest({
      headers: { Authorization: `Bearer ${userOneAccessToken}` },
      params: { userId: userOne.id.toString() },
    });
    const next = jest.fn();

    await auth('anyRight')(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith();
  });

  test('should call next with no errors if user has required rights', async () => {
    await insertUsers([admin]);
    const req = httpMocks.createRequest({
      headers: { Authorization: `Bearer ${adminAccessToken}` },
      params: { userId: userOne.id },
    });
    const next = jest.fn();

    await auth(...roleRights.get('admin'))(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith();
  });
});

describe('Utils pick function', () => {
  test('should correctly apply filter on name field', async () => {
    await insertUsers([userOne, userTwo, admin]);

    const res = await request(app)
      .get('/v1/users')
      .set('Authorization', `Bearer ${adminAccessToken}`)
      .query({ name: userOne.name })
      .send()
      .expect(httpStatus.OK);

    expect(res.body).toEqual({
      results: expect.any(Array),
      page: 1,
      limit: 10,
      totalPages: 1,
      totalResults: 1,
    });
    expect(res.body.results).toHaveLength(1);
    expect(res.body.results[0].id).toBe(userOne.id);
  });

  test('should correctly apply filter on role field', async () => {
    await insertUsers([userOne, userTwo, admin]);

    const res = await request(app)
      .get('/v1/users')
      .set('Authorization', `Bearer ${adminAccessToken}`)
      .query({ role: 'user' })
      .send()
      .expect(httpStatus.OK);
    expect(res.body).toEqual({
      results: expect.any(Array),
      page: 1,
      limit: 10,
      totalPages: 1,
      totalResults: 2,
    });
    expect(res.body.results).toHaveLength(2);
    expect(res.body.results[0].id).toBe(userOne.id);
    expect(res.body.results[1].id).toBe(userTwo.id);
  });

  test('should correctly sort the returned array if descending sort param is specified', async () => {
    await insertUsers([userOne, userTwo, admin]);

    const res = await request(app)
      .get('/v1/users')
      .set('Authorization', `Bearer ${adminAccessToken}`)
      .query({ sortBy: 'role:desc' })
      .send()
      .expect(httpStatus.OK);

    expect(res.body).toEqual({
      results: expect.any(Array),
      page: 1,
      limit: 10,
      totalPages: 1,
      totalResults: 3,
    });
    expect(res.body.results).toHaveLength(3);
    expect(res.body.results[0].id).toBe(userOne.id);
    expect(res.body.results[1].id).toBe(userTwo.id);
    expect(res.body.results[2].id).toBe(admin.id);
  });

  test('should correctly sort the returned array if ascending sort param is specified', async () => {
    await insertUsers([userOne, userTwo, admin]);

    const res = await request(app)
      .get('/v1/users')
      .set('Authorization', `Bearer ${adminAccessToken}`)
      .query({ sortBy: 'role:asc' })
      .send()
      .expect(httpStatus.OK);

    expect(res.body).toEqual({
      results: expect.any(Array),
      page: 1,
      limit: 10,
      totalPages: 1,
      totalResults: 3,
    });
    expect(res.body.results).toHaveLength(3);
    expect(res.body.results[0].id).toBe(admin.id);
    expect(res.body.results[1].id).toBe(userOne.id);
    expect(res.body.results[2].id).toBe(userTwo.id);
  });

  test('should correctly sort the returned array if multiple sorting criteria are specified', async () => {
    await insertUsers([userOne, userTwo, admin]);

    const res = await request(app)
      .get('/v1/users')
      .set('Authorization', `Bearer ${adminAccessToken}`)
      .query({ sortBy: 'role:desc,name:asc' })
      .send()
      .expect(httpStatus.OK);

    expect(res.body).toEqual({
      results: expect.any(Array),
      page: 1,
      limit: 10,
      totalPages: 1,
      totalResults: 3,
    });
    expect(res.body.results).toHaveLength(3);

    const expectedOrder = [userOne, userTwo, admin].sort((a, b) => {
      if (a.role < b.role) {
        return 1;
      }
      if (a.role > b.role) {
        return -1;
      }
      return a.name < b.name ? -1 : 1;
    });

    expectedOrder.forEach((user, index) => {
      expect(res.body.results[index].id).toBe(user.id);
    });
  });

  test('should limit returned array if limit param is specified', async () => {
    await insertUsers([userOne, userTwo, admin]);

    const res = await request(app)
      .get('/v1/users')
      .set('Authorization', `Bearer ${adminAccessToken}`)
      .query({ limit: 2 })
      .send()
      .expect(httpStatus.OK);

    expect(res.body).toEqual({
      results: expect.any(Array),
      page: 1,
      limit: 2,
      totalPages: 2,
      totalResults: 3,
    });
    expect(res.body.results).toHaveLength(2);
    expect(res.body.results[0].id).toBe(userOne.id);
    expect(res.body.results[1].id).toBe(userTwo.id);
  });

  test('should return the correct page if page and limit params are specified', async () => {
    await insertUsers([userOne, userTwo, admin]);

    const res = await request(app)
      .get('/v1/users')
      .set('Authorization', `Bearer ${adminAccessToken}`)
      .query({ page: 2, limit: 2 })
      .send()
      .expect(httpStatus.OK);

    expect(res.body).toEqual({
      results: expect.any(Array),
      page: 2,
      limit: 2,
      totalPages: 2,
      totalResults: 3,
    });
    expect(res.body.results).toHaveLength(1);
    expect(res.body.results[0].id).toBe(admin.id);
  });
});

describe('User routes', () => {
  describe('POST /v1/users', () => {
    let newUser;

    beforeEach(() => {
      newUser = {
        name: faker.name.findName(),
        email: faker.internet.email().toLowerCase(),
        password: 'password1',
        role: 'user',
      };
    });

    test('should return 201 and successfully create new user if data is ok', async () => {
      await insertUsers([admin]);

      const res = await request(app)
        .post('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newUser)
        .expect(httpStatus.CREATED);

      expect(res.body).not.toHaveProperty('password');
      expect(res.body).toEqual({
        id: expect.anything(),
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        isEmailVerified: false,
      });

      const dbUser = await userService.getUserById(res.body.id);
      expect(dbUser).toBeDefined();
      expect(dbUser.password).not.toBe(newUser.password);
      expect(dbUser).toMatchObject({ name: newUser.name, email: newUser.email, role: newUser.role, isEmailVerified: false });
    });

    test('should be able to create an admin as well', async () => {
      await insertUsers([admin]);
      newUser.role = 'admin';

      const res = await request(app)
        .post('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newUser)
        .expect(httpStatus.CREATED);

      expect(res.body.role).toBe('admin');

      const dbUser = await userService.getUserById(res.body.id);
      expect(dbUser.role).toBe('admin');
    });

    test('should return 401 error if access token is missing', async () => {
      await request(app).post('/v1/users').send(newUser).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 403 error if logged in user is not admin', async () => {
      await insertUsers([userOne]);

      await request(app)
        .post('/v1/users')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(newUser)
        .expect(httpStatus.FORBIDDEN);
    });

    test('should return 400 error if email is invalid', async () => {
      await insertUsers([admin]);
      newUser.email = 'invalidEmail';

      await request(app)
        .post('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newUser)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if email is already used', async () => {
      await insertUsers([admin, userOne]);
      newUser.email = userOne.email;

      await request(app)
        .post('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newUser)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if password length is less than 8 characters', async () => {
      await insertUsers([admin]);
      newUser.password = 'passwo1';

      await request(app)
        .post('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newUser)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if password does not contain both letters and numbers', async () => {
      await insertUsers([admin]);
      newUser.password = 'password';

      await request(app)
        .post('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newUser)
        .expect(httpStatus.BAD_REQUEST);

      newUser.password = '1111111';

      await request(app)
        .post('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newUser)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if role is neither user nor admin', async () => {
      await insertUsers([admin]);
      newUser.role = 'invalid';

      await request(app)
        .post('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newUser)
        .expect(httpStatus.BAD_REQUEST);
    });
  });

  describe('GET /v1/users', () => {
    test('should return 200 and apply the default query options', async () => {
      await insertUsers([userOne, userTwo, admin]);

      const res = await request(app)
        .get('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 10,
        totalPages: 1,
        totalResults: 3,
      });
      expect(res.body.results).toHaveLength(3);
      expect(res.body.results[0]).toEqual({
        id: userOne.id,
        name: userOne.name,
        email: userOne.email,
        role: userOne.role,
        isEmailVerified: userOne.isEmailVerified,
      });
    });

    test('should return 401 if access token is missing', async () => {
      await insertUsers([userOne, userTwo, admin]);

      await request(app).get('/v1/users').send().expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 403 if a non-admin is trying to access all users', async () => {
      await insertUsers([userOne, userTwo, admin]);

      await request(app)
        .get('/v1/users')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send()
        .expect(httpStatus.FORBIDDEN);
    });

    test('should correctly apply filter on name field', async () => {
      await insertUsers([userOne, userTwo, admin]);

      const res = await request(app)
        .get('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .query({ name: userOne.name })
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 10,
        totalPages: 1,
        totalResults: 1,
      });
      expect(res.body.results).toHaveLength(1);
      expect(res.body.results[0].id).toBe(userOne.id);
    });

    test('should correctly apply filter on role field', async () => {
      await insertUsers([userOne, userTwo, admin]);

      const res = await request(app)
        .get('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .query({ role: 'user' })
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 10,
        totalPages: 1,
        totalResults: 2,
      });
      expect(res.body.results).toHaveLength(2);
      expect(res.body.results[0].id).toBe(userOne.id);
      expect(res.body.results[1].id).toBe(userTwo.id);
    });

    test('should correctly sort the returned array if descending sort param is specified', async () => {
      await insertUsers([userOne, userTwo, admin]);

      const res = await request(app)
        .get('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .query({ sortBy: 'role:desc' })
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 10,
        totalPages: 1,
        totalResults: 3,
      });
      expect(res.body.results).toHaveLength(3);
      expect(res.body.results[0].id).toBe(userOne.id);
      expect(res.body.results[1].id).toBe(userTwo.id);
      expect(res.body.results[2].id).toBe(admin.id);
    });

    test('should correctly sort the returned array if ascending sort param is specified', async () => {
      await insertUsers([userOne, userTwo, admin]);

      const res = await request(app)
        .get('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .query({ sortBy: 'role:asc' })
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 10,
        totalPages: 1,
        totalResults: 3,
      });
      expect(res.body.results).toHaveLength(3);
      expect(res.body.results[0].id).toBe(admin.id);
      expect(res.body.results[1].id).toBe(userOne.id);
      expect(res.body.results[2].id).toBe(userTwo.id);
    });

    test('should correctly sort the returned array if multiple sorting criteria are specified', async () => {
      await insertUsers([userOne, userTwo, admin]);

      const res = await request(app)
        .get('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .query({ sortBy: 'role:desc,name:asc' })
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 10,
        totalPages: 1,
        totalResults: 3,
      });
      expect(res.body.results).toHaveLength(3);

      const expectedOrder = [userOne, userTwo, admin].sort((a, b) => {
        if (a.role < b.role) {
          return 1;
        }
        if (a.role > b.role) {
          return -1;
        }
        return a.name < b.name ? -1 : 1;
      });

      expectedOrder.forEach((user, index) => {
        expect(res.body.results[index].id).toBe(user.id);
      });
    });

    test('should limit returned array if limit param is specified', async () => {
      await insertUsers([userOne, userTwo, admin]);

      const res = await request(app)
        .get('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .query({ limit: 2 })
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 2,
        totalPages: 2,
        totalResults: 3,
      });
      expect(res.body.results).toHaveLength(2);
      expect(res.body.results[0].id).toBe(userOne.id);
      expect(res.body.results[1].id).toBe(userTwo.id);
    });

    test('should return the correct page if page and limit params are specified', async () => {
      await insertUsers([userOne, userTwo, admin]);

      const res = await request(app)
        .get('/v1/users')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .query({ page: 2, limit: 2 })
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 2,
        limit: 2,
        totalPages: 2,
        totalResults: 3,
      });
      expect(res.body.results).toHaveLength(1);
      expect(res.body.results[0].id).toBe(admin.id);
    });
  });

  describe('GET /v1/users/:userId', () => {
    test('should return 200 and the user object if data is ok', async () => {
      await insertUsers([userOne]);

      const res = await request(app)
        .get(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send()
        .expect(httpStatus.OK);

      expect(res.body).not.toHaveProperty('password');
      expect(res.body).toEqual({
        id: userOne.id,
        email: userOne.email,
        name: userOne.name,
        role: userOne.role,
        isEmailVerified: userOne.isEmailVerified,
      });
    });

    test('should return 401 error if access token is missing', async () => {
      await insertUsers([userOne]);

      await request(app).get(`/v1/users/${userOne.id}`).send().expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 403 error if user is trying to get another user', async () => {
      await insertUsers([userOne, userTwo]);

      await request(app)
        .get(`/v1/users/${userTwo.id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send()
        .expect(httpStatus.FORBIDDEN);
    });

    test('should return 200 and the user object if admin is trying to get another user', async () => {
      await insertUsers([userOne, admin]);

      await request(app)
        .get(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send()
        .expect(httpStatus.OK);
    });

    test('should return 400 error if userId is not a valid mongo id', async () => {
      await insertUsers([admin]);

      await request(app)
        .get('/v1/users/invalidId')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send()
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 404 error if user is not found', async () => {
      await insertUsers([admin]);

      await request(app)
        .get(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send()
        .expect(httpStatus.NOT_FOUND);
    });
  });

  describe('DELETE /v1/users/:userId', () => {
    test('should return 204 if data is ok', async () => {
      await insertUsers([userOne]);

      await request(app)
        .delete(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send()
        .expect(httpStatus.NO_CONTENT);

      const dbUser = await userService.getUserById(userOne.id);
      expect(dbUser).toBeNull();
    });

    test('should return 401 error if access token is missing', async () => {
      await insertUsers([userOne]);

      await request(app).delete(`/v1/users/${userOne.id}`).send().expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 403 error if user is trying to delete another user', async () => {
      await insertUsers([userOne, userTwo]);

      await request(app)
        .delete(`/v1/users/${userTwo.id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send()
        .expect(httpStatus.FORBIDDEN);
    });

    test('should return 204 if admin is trying to delete another user', async () => {
      await insertUsers([userOne, admin]);

      await request(app)
        .delete(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send()
        .expect(httpStatus.NO_CONTENT);
    });

    test('should return 400 error if userId is not a valid mongo id', async () => {
      await insertUsers([admin]);

      await request(app)
        .delete('/v1/users/invalidId')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send()
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 404 error if user already is not found', async () => {
      await insertUsers([admin]);

      await request(app)
        .delete(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send()
        .expect(httpStatus.NOT_FOUND);
    });
  });

  describe('PATCH /v1/users/:userId', () => {
    test('should return 200 and successfully update user if data is ok', async () => {
      await insertUsers([userOne]);
      const updateBody = {
        name: faker.name.findName(),
        email: faker.internet.email().toLowerCase(),
        password: 'newPassword1',
      };

      const res = await request(app)
        .patch(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.OK);

      expect(res.body).not.toHaveProperty('password');
      expect(res.body).toEqual({
        id: userOne.id,
        name: updateBody.name,
        email: updateBody.email,
        role: 'user',
        isEmailVerified: false,
      });

      const dbUser = await userService.getUserById(userOne.id);
      expect(dbUser).toBeDefined();
      expect(dbUser.password).not.toBe(updateBody.password);
      expect(dbUser).toMatchObject({ name: updateBody.name, email: updateBody.email, role: 'user' });
    });

    test('should return 401 error if access token is missing', async () => {
      await insertUsers([userOne]);
      const updateBody = { name: faker.name.findName() };

      await request(app).patch(`/v1/users/${userOne.id}`).send(updateBody).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 403 if user is updating another user', async () => {
      await insertUsers([userOne, userTwo]);
      const updateBody = { name: faker.name.findName() };

      await request(app)
        .patch(`/v1/users/${userTwo.id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.FORBIDDEN);
    });

    test('should return 200 and successfully update user if admin is updating another user', async () => {
      await insertUsers([userOne, admin]);
      const updateBody = { name: faker.name.findName() };

      await request(app)
        .patch(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.OK);
    });

    test('should return 404 if admin is updating another user that is not found', async () => {
      await insertUsers([admin]);
      const updateBody = { name: faker.name.findName() };

      await request(app)
        .patch(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.NOT_FOUND);
    });

    test('should return 400 error if userId is not a valid mongo id', async () => {
      await insertUsers([admin]);
      const updateBody = { name: faker.name.findName() };

      await request(app)
        .patch(`/v1/users/invalidId`)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 if email is invalid', async () => {
      await insertUsers([userOne]);
      const updateBody = { email: 'invalidEmail' };

      await request(app)
        .patch(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 if email is already taken', async () => {
      await insertUsers([userOne, userTwo]);
      const updateBody = { email: userTwo.email };

      await request(app)
        .patch(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should not return 400 if email is my email', async () => {
      await insertUsers([userOne]);
      const updateBody = { email: userOne.email };

      await request(app)
        .patch(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.OK);
    });

    test('should return 400 if password length is less than 8 characters', async () => {
      await insertUsers([userOne]);
      const updateBody = { password: 'passwo1' };

      await request(app)
        .patch(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 if password does not contain both letters and numbers', async () => {
      await insertUsers([userOne]);
      const updateBody = { password: 'password' };

      await request(app)
        .patch(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.BAD_REQUEST);

      updateBody.password = '11111111';

      await request(app)
        .patch(`/v1/users/${userOne.id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.BAD_REQUEST);
    });
  });
});

describe('Utils pick function', () => {
  test('should correctly apply filter on name field', async () => {
    await insertUsers([userOne, userTwo, admin]);

    const query = { name: userOne.name };
    const filter = pick(query, ['name', 'role']);
    const options = pick(query, ['sortBy', 'limit', 'page']);
    const res = await User.paginate(filter, options);
    expect(res).toEqual({
      results: expect.any(Array),
      page: 1,
      limit: 10,
      totalPages: 1,
      totalResults: 1,
    });
    expect(res.results).toHaveLength(1);
    expect(res.results[0].id).toBe(userOne.id);
  });

  test('should correctly apply filter on role field', async () => {
    await insertUsers([userOne, userTwo, admin]);

    const query = { role: 'user' };
    const filter = pick(query, ['name', 'role']);
    const options = pick(query, ['sortBy', 'limit', 'page']);
    const res = await User.paginate(filter, options);

    expect(res).toEqual({
      results: expect.any(Array),
      page: 1,
      limit: 10,
      totalPages: 1,
      totalResults: 2,
    });
    expect(res.results).toHaveLength(2);
    expect(res.results[0].id).toBe(userOne.id);
    expect(res.results[1].id).toBe(userTwo.id);
  });

  test('should correctly sort the returned array if descending sort param is specified', async () => {
    await insertUsers([userOne, userTwo, admin]);

    const query = { sortBy: 'role:desc' };
    const filter = pick(query, ['name', 'role']);
    const options = pick(query, ['sortBy', 'limit', 'page']);
    const res = await User.paginate(filter, options);

    expect(res).toEqual({
      results: expect.any(Array),
      page: 1,
      limit: 10,
      totalPages: 1,
      totalResults: 3,
    });
    expect(res.results).toHaveLength(3);
    expect(res.results[0].id).toBe(userOne.id);
    expect(res.results[1].id).toBe(userTwo.id);
    expect(res.results[2].id).toBe(admin.id);
  });

  test('should correctly sort the returned array if ascending sort param is specified', async () => {
    await insertUsers([userOne, userTwo, admin]);

    const query = { sortBy: 'role:asc' };
    const filter = pick(query, ['name', 'role']);
    const options = pick(query, ['sortBy', 'limit', 'page']);
    const res = await User.paginate(filter, options);

    expect(res).toEqual({
      results: expect.any(Array),
      page: 1,
      limit: 10,
      totalPages: 1,
      totalResults: 3,
    });
    expect(res.results).toHaveLength(3);
    expect(res.results[0].id).toBe(admin.id);
    expect(res.results[1].id).toBe(userOne.id);
    expect(res.results[2].id).toBe(userTwo.id);
  });

  test('should correctly sort the returned array if multiple sorting criteria are specified', async () => {
    await insertUsers([userOne, userTwo, admin]);

    const query = { sortBy: 'role:desc,name:asc' };
    const filter = pick(query, ['name', 'role']);
    const options = pick(query, ['sortBy', 'limit', 'page']);
    const res = await User.paginate(filter, options);

    expect(res).toEqual({
      results: expect.any(Array),
      page: 1,
      limit: 10,
      totalPages: 1,
      totalResults: 3,
    });
    expect(res.results).toHaveLength(3);

    const expectedOrder = [userOne, userTwo, admin].sort((a, b) => {
      if (a.role < b.role) {
        return 1;
      }
      if (a.role > b.role) {
        return -1;
      }
      return a.name < b.name ? -1 : 1;
    });

    expectedOrder.forEach((user, index) => {
      expect(res.results[index].id).toBe(user.id);
    });
  });

  test('should limit returned array if limit param is specified', async () => {
    await insertUsers([userOne, userTwo, admin]);

    const query = { limit: 2 };
    const filter = pick(query, ['name', 'role']);
    const options = pick(query, ['sortBy', 'limit', 'page']);
    const res = await User.paginate(filter, options);
    expect(res).toEqual({
      results: expect.any(Array),
      page: 1,
      limit: 2,
      totalPages: 2,
      totalResults: 3,
    });
    expect(res.results).toHaveLength(2);
    expect(res.results[0].id).toBe(userOne.id);
    expect(res.results[1].id).toBe(userTwo.id);
  });

  test('should return the correct page if page and limit params are specified', async () => {
    await insertUsers([userOne, userTwo, admin]);

    const query = { page: 2, limit: 2 };
    const filter = pick(query, ['name', 'role']);
    const options = pick(query, ['sortBy', 'limit', 'page']);
    const res = await User.paginate(filter, options);

    expect(res).toEqual({
      results: expect.any(Array),
      page: 2,
      limit: 2,
      totalPages: 2,
      totalResults: 3,
    });
    expect(res.results).toHaveLength(1);
    expect(res.results[0].id).toBe(admin.id);
  });
});

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

describe('Utils pick function', () => {
  test('pick sortBy role:desc', async () => {
    const query = { sortBy: 'role:desc' };
    const filter = pick(query, ['name', 'role']);
    const options = pick(query, ['sortBy', 'limit', 'page']);
    expect({ filter, options }).toEqual({ filter: {}, options: { sortBy: 'role:desc' } });
  });

  test('pick sortBy', async () => {
    const query = { sortBy: 'role:desc,name:asc' };
    const filter = pick(query, ['name', 'role']);
    const options = pick(query, ['sortBy', 'limit', 'page']);
    expect({ filter, options }).toEqual({ filter: {}, options: { sortBy: 'role:desc,name:asc' } });
  });

  test('pick limit', async () => {
    const query = { limit: 2 };
    const filter = pick(query, ['name', 'role']);
    const options = pick(query, ['sortBy', 'limit', 'page']);
    expect({ filter, options }).toEqual({ filter: {}, options: { limit: 2 } });
  });

  test('pick filter name', async () => {
    const query = { name: 'userOne name' };
    const filter = pick(query, ['name', 'role']);
    const options = pick(query, ['sortBy', 'limit', 'page']);
    expect({ filter, options }).toEqual({ filter: { name: 'userOne name' }, options: {} });
  });

  test('pick filter role', async () => {
    const query = { role: 'user' };
    const filter = pick(query, ['name', 'role']);
    const options = pick(query, ['sortBy', 'limit', 'page']);
    expect({ filter, options }).toEqual({ filter: { role: 'user' }, options: {} });
  });

  test('pick filter name and role', async () => {
    const query = { name: 'userOne name', role: 'user' };
    const filter = pick(query, ['name', 'role']);
    const options = pick(query, ['sortBy', 'limit', 'page']);
    expect({ filter, options }).toEqual({ filter: { name: 'userOne name', role: 'user' }, options: {} });
  });

  test('pick all', async () => {
    const query = { role: 'user', sortBy: 'role:desc,name:asc', limit: 12, page: 2 };
    const filter = pick(query, ['name', 'role']);
    const options = pick(query, ['sortBy', 'limit', 'page']);
    expect({ filter, options }).toEqual({
      filter: { role: 'user' },
      options: { sortBy: 'role:desc,name:asc', limit: 12, page: 2 },
    });
  });
});
