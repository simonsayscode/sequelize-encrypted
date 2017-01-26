var crypto = require('crypto');

function EncryptedField(Sequelize, key, opt) {
    if (!(this instanceof EncryptedField)) {
        return new EncryptedField(Sequelize, key, opt);
    }

    var self = this;
    self.salt = key;
    self.key = new Buffer(key, 'hex');
    self.Sequelize = Sequelize;

    opt = opt || {};
    self._algorithm = opt.algorithm || 'aes-256-cbc';
    self._iv_length = opt.iv_length || 16;
    self.encrypted_field_name = undefined;
    self.encrypted_fields = [];
};

EncryptedField.prototype.vault = function(name) {
    var self = this;

    if (self.encrypted_field_name) {
        throw new Error(`Vault '${self.encrypted_field_name}' already initialized!`);
    }

    self.encrypted_field_name = name;

    return {
        type: self.Sequelize.BLOB,
        get: function() {
            var previous = this.getDataValue(name);
            if (!previous) {
                return {};
            }

            previous = new Buffer(previous);

            var iv = previous.slice(0, self._iv_length);
            var content = previous.slice(self._iv_length, previous.length);
            var decipher = crypto.createDecipheriv(self._algorithm, self.key, iv);

            var json = decipher.update(content, undefined, 'utf8') + decipher.final('utf8');
            return JSON.parse(json);
        },
        set: function(value) {
            // if new data is set, we will use a new IV
            var new_iv = crypto.randomBytes(self._iv_length);

            var cipher = crypto.createCipheriv(self._algorithm, self.key, new_iv);

            cipher.end(JSON.stringify(value), 'utf-8');
            var enc_final = Buffer.concat([new_iv, cipher.read()]);
            var previous = this.setDataValue(name, enc_final);
        }
    }
};

EncryptedField.hash = function(model, salt, value) {
    if (!value || value === '') {
        return null;
    }
    const hash = crypto.createHash('sha256');
    hash.update(model + salt + value);
    return hash.digest('hex');
}

EncryptedField.prototype.digest = function(options) {
    var self = this;
    return Object.assign({
        type: self.Sequelize.STRING,
        validate: {
          notEmpty: true,
        },
    }, options || {});
}

EncryptedField.prototype.field = function(name, config) {
    var self = this;
    config = Object.assign({}, config || {});

    var hasValidations = !!config.validate;

    if (!self.encrypted_field_name) {
        throw new Error('you must initialize the vault field before using encrypted fields');
    }

    var encrypted_field_name = self.encrypted_field_name;

    if (~self.encrypted_fields.indexOf(name)) {
        throw new Error('this field name has already been used: ' + name);
    }
    self.encrypted_fields.push(name);

    return {
        type: self.Sequelize.VIRTUAL(config.type || null),
        set: function set_encrypted(val) {
            // trigger the validations
            if (hasValidations) {
                this.setDataValue(name, val);
            }

            // use `this` not self because we need to reference the sequelize instance
            // not our EncryptedField instance
            var encrypted = this[encrypted_field_name];
            encrypted[name] = val;
            this[encrypted_field_name] = encrypted;

            if (config.digest) {
                const modelName = this.$modelOptions.name.singular;
                const digest = EncryptedField.hash(modelName, self.salt, val);
                this.setDataValue(config.digest, digest);
            }
        },
        get: function get_encrypted() {
            var encrypted = this[encrypted_field_name];
            var val = encrypted[name];
            return (!~[undefined, null].indexOf(val)) ? val : config.defaultValue;
        },
        allowNull: !~[undefined, null].indexOf(config.allowNull) ? config.allowNull : true,
        validate: config.validate,
    }
};

module.exports = EncryptedField;
