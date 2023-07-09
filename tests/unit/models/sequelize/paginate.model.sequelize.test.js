const pick = require('../../../../src/utils/pick');
const { User } = require('../../../../src/models/sequelize');
const { userOne, userTwo, admin, insertUsers } = require('../../../fixtures/sequelize/user.sequelize.fixture');
const setupTestDB = require('../../../utils/setupTestDB.sequelize');

setupTestDB();

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
