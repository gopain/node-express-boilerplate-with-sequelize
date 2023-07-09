const pick = require('../../src/utils/pick');

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
