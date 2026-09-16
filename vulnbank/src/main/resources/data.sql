-- Passwords are stored as unsalted MD5 (A02: Cryptographic Failures).
-- 'password123' -> 482c811da5d5b4bc6d497ffa98491e38
-- 'admin'       -> 21232f297a57a5a743894a0e4a801fc3
INSERT INTO users (id, username, password, role, full_name) VALUES
 (1, 'alice', '482c811da5d5b4bc6d497ffa98491e38', 'USER', 'Alice Johnson'),
 (2, 'bob',   '482c811da5d5b4bc6d497ffa98491e38', 'USER', 'Bob Smith'),
 (3, 'admin', '21232f297a57a5a743894a0e4a801fc3', 'ADMIN', 'System Administrator');

INSERT INTO accounts (id, owner_id, account_number, balance) VALUES
 (1, 1, 'ACC-1001', 5000.00),
 (2, 2, 'ACC-1002', 12500.50),
 (3, 3, 'ACC-9000', 999999.99);

INSERT INTO messages (id, sender, content) VALUES
 (1, 'alice', 'Hi support, when will my card arrive?'),
 (2, 'bob', 'Thanks for the quick help yesterday!');
