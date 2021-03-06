import assert from 'assert';
import Sequelize from 'sequelize';
import EncryptedField from '../';

const sequelize = new Sequelize('postgres://localhost:5432/postgres');

const key1 = 'a593e7f567d01031d153b5af6d9a25766b95926cff91c6be3438c7f7ac37230e';
const key2 = 'a593e7f567d01031d153b5af6d9a25766b95926cff91c6be3438c7f7ac37230f';

const v1 = EncryptedField(Sequelize, key1);
const v2 = EncryptedField(Sequelize, key2);

describe('sequelize-encrypted', () => {

    const User = sequelize.define('user', {
        name: Sequelize.STRING,
        encrypted: v1.vault('encrypted'),
        another_encrypted: v2.vault('another_encrypted'),
        encrypted_hash: Sequelize.STRING,
        // creating digest column for testing
        digest: v1.digest(),

        // encrypted virtual fields
        private_1: v1.field('private_1'),
        private_2: v2.field('private_2'),
    });

    before('create models', async () => {
        await User.sync({force: true});
    });

    it('should save an encrypted field', async () => {
        const user = User.build();
        user.private_1 = 'test';

        await user.save();
        const found = await User.findByPk(user.id);
        assert.equal(found.private_1, user.private_1);
    });

    it('should support multiple encrypted fields', async() => {
        const user = User.build();
        user.private_1 = 'baz';
        user.private_2 = 'foobar';
        await user.save();

        const vault = EncryptedField(Sequelize, key2);

        const AnotherUser = sequelize.define('user', {
            name: Sequelize.STRING,
            another_encrypted: vault.vault('another_encrypted'),
            private_2: vault.field('private_2'),
            private_1: vault.field('private_1'),
        });

        const found = await AnotherUser.findByPk(user.id);
        assert.equal(found.private_2, user.private_2);

        // encrypted with key1 and different field originally
        // and thus can't be recovered with key2
        assert.equal(found.private_1, undefined);
    });

    it('should throw error on decryption using invalid key', async() => {
        // attempt to use key2 for vault encrypted with key1
        const badEncryptedField = EncryptedField(Sequelize, key2);
        const BadEncryptionUser = sequelize.define('user', {
            name: Sequelize.STRING,
            encrypted: badEncryptedField.vault('encrypted'),
            private_1: badEncryptedField.field('private_1'),
        });

        const model = User.build();
        model.private_1 = 'secret!';
        await model.save();

        let threw;
        try {
            const found = await BadEncryptionUser.findByPk(model.id)
            found.private_1; // trigger decryption
        } catch (error) {
            threw = error;
        }

        assert.ok(threw && /bad decrypt$/.test(threw.message),
            'should have thrown decryption error');
    });

    it('should support extra decryption keys (to facilitate key rotation)', async() => {
        const keyOneEncryptedField = EncryptedField(Sequelize, key1);
        const keyTwoAndOneEncryptedField = EncryptedField(Sequelize, key2, {
          extraDecryptionKeys: [key1],
        });

        // models both access the same table, with different encryption keys
        const KeyOneModel = sequelize.define('rotateMe', {
            encrypted: keyOneEncryptedField.vault('encrypted'),
            private: keyOneEncryptedField.field('private'),
        });
        const KeyTwoAndOneModel = sequelize.define('rotateMe', {
            encrypted: keyTwoAndOneEncryptedField.vault('encrypted'),
            private: keyTwoAndOneEncryptedField.field('private'),
        });

        await KeyOneModel.sync({force: true});

        const modelUsingKeyOne = KeyOneModel.build();
        const modelUsingKeyTwo = KeyTwoAndOneModel.build();
        modelUsingKeyOne.private = 'secret!';
        modelUsingKeyTwo.private = 'also secret!';
        await Promise.all([
            modelUsingKeyOne.save(),
            modelUsingKeyTwo.save(),
        ]);

        // note: both sets of data accessed via KeyTwoAndOneModel
        const foundFromKeyOne = await KeyTwoAndOneModel.findByPk(modelUsingKeyOne.id);
        const foundFromKeyTwo = await KeyTwoAndOneModel.findByPk(modelUsingKeyTwo.id);

        assert.equal(foundFromKeyOne.private, modelUsingKeyOne.private);
        assert.equal(foundFromKeyTwo.private, modelUsingKeyTwo.private);
    });

    it('should support validation', async() => {
      const vault = EncryptedField(Sequelize, key2);
      const ValidUser = sequelize.define('validUser', {
          name: Sequelize.STRING,
          encrypted: vault.vault('encrypted'),

          // encrypted virtual fields
          private_1: vault.field('private_1', {
            type: Sequelize.INTEGER,
            validate: {
              notEmpty: true
            }
          })
      });
      const user = ValidUser.build();
      user.private_1 = '';

      assert.throws(user.validate, Error, 'Validation error: Validation notEmpty on private_1 failed');
    });

    it('should support defaultValue', async() => {
      const vault = EncryptedField(Sequelize, key2);
      const ValidUser = sequelize.define('validUser', {
          name: Sequelize.STRING,
          encrypted: vault.vault('encrypted'),

          // encrypted virtual fields
          private_1: vault.field('private_1', {
            defaultValue: 'hello'
          })
      });
      const user = ValidUser.build();
      assert.equal(user.private_1, 'hello');
    });

    it('should support allowNull', async() => {
      const vault = EncryptedField(Sequelize, key2);
      const ValidUser = sequelize.define('validUser', {
          name: Sequelize.STRING,
          encrypted: vault.vault('encrypted'),

          // encrypted virtual fields
          private_1: vault.field('private_1', {
            allowNull: false
          })
      });
      const user = ValidUser.build();

      assert.throws(user.validate, Error, 'notNull Violation: validUser.private_1 cannot be null');
    });

    it('should support digest fields', async() => {
      const vault = EncryptedField(Sequelize, key2);
      const User = sequelize.define('user', {
        name: Sequelize.STRING,
        encrypted: vault.vault('encrypted'),
        digest: vault.digest(),

        // encrypted virtual fields
        private_1: vault.field('private_1', {
          digest: 'digest'
        })
      });
      const user = User.build();
      user.private_1 = 'test';

      await user.save();
      const found = await User.findByPk(user.id);
      assert.equal(found.digest, EncryptedField.hash('user', key2, 'test'));
    });


  it('digest fields should only be accessible with the same key as its vault', async() => {
    const vault = EncryptedField(Sequelize, key2);
    const User = sequelize.define('user', {
      name: Sequelize.STRING,
      encrypted: vault.vault('encrypted'),
      digest: vault.digest(),

      // encrypted virtual fields
      private_1: vault.field('private_1', {
        digest: 'digest'
      })
    });
    const user = User.build();
    user.private_1 = 'test';

    await user.save();
    const found = await User.findByPk(user.id);
    assert.notEqual(found.digest, EncryptedField.hash('user', key1, 'test'));
  });
});
