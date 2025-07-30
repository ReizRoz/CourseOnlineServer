const bcrypt = require('bcryptjs');

module.exports = (db) => {
  return {
    create: (name, email, password, role, callback) => {
      const sql = 'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)';
      db.run(sql, [name, email, password, role], function(err) {
        callback(err, this?.lastID);
      });
    },

    findByEmail: (email, callback) => {
      const sql = 'SELECT * FROM users WHERE email = ?';
      db.get(sql, [email], callback);
    },

    findById: (id, callback) => {
      const sql = 'SELECT * FROM users WHERE id = ?';
      db.get(sql, [id], callback);
    },

    findAll: (callback) => {
      const sql = 'SELECT * FROM users';
      db.all(sql, callback);
    },

    updateById: async (id, updates, callback) => {
      try {
        const fields = [];
        const values = [];

        // טיפוסי: רק אם name/email/role קיימים – נוסיף אותם
        if (updates.name !== undefined) {
          fields.push('name = ?');
          values.push(updates.name);
        }
        if (updates.email !== undefined) {
          fields.push('email = ?');
          values.push(updates.email);
        }
        if (updates.role !== undefined) {
          fields.push('role = ?');
          values.push(updates.role);
        }

        // אם יש סיסמה – להצפין לפני השמירה
        if (updates.password) {
          const hashedPassword = await bcrypt.hash(updates.password, 10);
          fields.push('password = ?');
          values.push(hashedPassword);
        }

        if (fields.length === 0) {
          return callback(new Error('No fields to update.'));
        }

        const sql = `UPDATE users SET ${fields.join(', ')} WHERE id = ?`;
        values.push(id);

        db.run(sql, values, function(err) {
          if (err) {
            return callback(err);
          }
          callback(null);
        });
      } catch (err) {
        callback(new Error('Failed to process password during update.'));
      }
    },

    deleteById: (id, callback) => {
      const sql = 'DELETE FROM users WHERE id = ?';
      db.run(sql, [id], callback);
    }
  };
};
