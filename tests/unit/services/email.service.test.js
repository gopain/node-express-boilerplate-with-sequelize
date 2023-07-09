const { sendEmail, sendResetPasswordEmail, sendVerificationEmail } = require('../../../src/services/email.service');

describe('eMail Service', () => {
  test('send eMail', async () => {
    await sendEmail('legend102@qq.com', '测试邮件', '这是一个测试邮件');
    await sendResetPasswordEmail('legend102@qq.com', 'sendResetPasswordEmail');
    await sendVerificationEmail('legend102@qq.com', 'sendResetPasswordEmail');
  });
});
