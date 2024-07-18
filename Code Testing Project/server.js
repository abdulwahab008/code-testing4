import express from 'express';
import mysql from 'mysql2/promise';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 4000;
const JWT_SECRET = 'your_jwt_secret'; 

// MySQL connection configuration
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: 'Punjab123',
  database: 'testing',
};

// Create MySQL connection pool
const pool = mysql.createPool(dbConfig);

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

app.post('/api/check', (req, res) => {
    console.log('Request received:', req.body);
    const code = req.body.code;
    if (!code) {
        return res.status(400).json({ error: 'Code is required' });
    }
    const result = checkVulnerabilities(code);
    res.json(result);
});

function checkVulnerabilities(code) {
  const vulnerabilities = {
    XSS: [],
    CodeInjection: [],
    SQLInjection: [],
    Authentication: []
  };

  // Total number of rules for each type
  const totalRules = {
    XSS: 15,
    CodeInjection: 11,
    SQLInjection: 12,
    Authentication: 6
  };

  // Log the initial total rules
  console.log('Total Rules:', totalRules);



  // XSS Checks
  if (/innerHTML\s*=\s*/.test(code) || /outerHTML\s*=\s*/.test(code)) {
    vulnerabilities.XSS.push('Use of innerHTML/outerHTML');
  }
  if (/document\.write\s*\(/.test(code)) {
    vulnerabilities.XSS.push('Use of document.write()');
  }
  if (/<script>.*<\/script>/.test(code)) {
    vulnerabilities.XSS.push('Potential XSS with inline scripts');
  }
  if (/(<.*script.*>)/i.test(code)) {
    vulnerabilities.XSS.push('Potential XSS from user input with script tags');
  }
  const locationHrefRegex = /location\.href\s*=\s*['"]([^'"]+)['"]/;
  const locationHrefMatches = code.match(locationHrefRegex);
  if (locationHrefMatches) {
    const assignment = locationHrefMatches[1];
    if (!/^\/[^\/].*/.test(assignment) && !/^\.\//.test(assignment)) {
      vulnerabilities.XSS.push('Potential XSS from location.href assignment');
    }
  }
  if (/window\.location\s*=\s*/.test(code)) {
    vulnerabilities.XSS.push('Potential XSS from window.location assignment');
  }
  if (/onerror\s*=\s*/.test(code)) {
    vulnerabilities.XSS.push('Potential XSS from onerror attribute');
  }
  if (/onload\s*=\s*/.test(code)) {
    vulnerabilities.XSS.push('Potential XSS from onload attribute');
  }
  if (/srcdoc\s*=\s*/.test(code)) {
    vulnerabilities.XSS.push('Potential XSS from srcdoc attribute');
  }
  if (/javascript:/.test(code)) {
    vulnerabilities.XSS.push('Potential XSS from javascript: URL scheme');
  }
  if (/document\.URL\s*=\s*/.test(code)) {
    vulnerabilities.XSS.push('Potential XSS from document.URL assignment');
  }
  if (/innerHTML\s*\+=\s*/.test(code)) {
    vulnerabilities.XSS.push('Potential XSS from concatenation with innerHTML');
  }

  // Code Injection Checks
  if (/eval\s*\(/.test(code)) {
    vulnerabilities.CodeInjection.push('Use of eval()');
  }
  if (/new Function\s*\(/.test(code)) {
    vulnerabilities.CodeInjection.push('Use of new Function()');
  }
  if (/setTimeout\s*\(\s*.*\s*,\s*.*\s*\)/.test(code)) {
    vulnerabilities.CodeInjection.push('Use of setTimeout with dynamic code');
  }
  if (/setInterval\s*\(\s*.*\s*,\s*.*\s*\)/.test(code)) {
    vulnerabilities.CodeInjection.push('Use of setInterval with dynamic code');
  }
  if (/exec\s*\(/.test(code)) {
    vulnerabilities.CodeInjection.push('Use of exec() in server-side code');
  }
  if (/spawn\s*\(/.test(code)) {
    vulnerabilities.CodeInjection.push('Use of spawn() in server-side code');
  }
  if (/require\s*\(/.test(code)) {
    vulnerabilities.CodeInjection.push('Use of require() in server-side code');
  }
  if (/import\s*\(/.test(code)) {
    vulnerabilities.CodeInjection.push('Use of import() in server-side code');
  }
  if (/process\.exec\s*\(/.test(code)) {
    vulnerabilities.CodeInjection.push('Use of process.exec() in server-side code');
  }
  if (/child_process\.exec\s*\(/.test(code)) {
    vulnerabilities.CodeInjection.push('Use of child_process.exec() in server-side code');
  }
  if (/child_process\.spawn\s*\(/.test(code)) {
    vulnerabilities.CodeInjection.push('Use of child_process.spawn() in server-side code');
  }

  // SQL Injection Checks
  if (/SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=/.test(code)) {
    vulnerabilities.SQLInjection.push('Potential SQL Injection with SELECT statement');
  }
  if (/INSERT\s+INTO\s+.*\s+VALUES\s*\(.*\)/.test(code)) {
    vulnerabilities.SQLInjection.push('Potential SQL Injection with INSERT statement');
  }
  if (/UPDATE\s+.*\s+SET\s+.*\s+WHERE\s+.*=/.test(code)) {
    vulnerabilities.SQLInjection.push('Potential SQL Injection with UPDATE statement');
  }
  if (/DELETE\s+FROM\s+.*\s+WHERE\s+.*=/.test(code)) {
    vulnerabilities.SQLInjection.push('Potential SQL Injection with DELETE statement');
  }
  if (/DROP\s+TABLE\s+.*;/.test(code)) {
    vulnerabilities.SQLInjection.push('Potential SQL Injection with DROP statement');
  }
  if (/ALTER\s+TABLE\s+.*\s+ADD\s+/.test(code)) {
    vulnerabilities.SQLInjection.push('Potential SQL Injection with ALTER statement');
  }
  if (/CREATE\s+TABLE\s+.*\s*\(.*\)/.test(code)) {
    vulnerabilities.SQLInjection.push('Potential SQL Injection with CREATE statement');
  }
  if (/UNION\s+SELECT\s+.*\s+FROM\s+.*;/.test(code)) {
    vulnerabilities.SQLInjection.push('Potential SQL Injection with UNION SELECT statement');
  }
  if (/EXEC\s+.*\s*\(.*\)/.test(code)) {
    vulnerabilities.SQLInjection.push('Potential SQL Injection with EXEC statement');
  }
  if (/CONCAT\s*\(.*\)/.test(code)) {
    vulnerabilities.SQLInjection.push('Potential SQL Injection with CONCAT function');
  }
  if (/CAST\s*\(.*\)/.test(code)) {
    vulnerabilities.SQLInjection.push('Potential SQL Injection with CAST function');
  }

  // Authentication Vulnerability Checks
  if (/jwt\.sign\s*\(.*,\s*['"`](.*)['"`]\s*,/.test(code)) {
    vulnerabilities.Authentication.push('Potential hardcoded JWT secret');
  }
  if (/bcrypt\.hashSync\s*\(.*,\s*['"`](.*)['"`]\s*\)/.test(code)) {
    vulnerabilities.Authentication.push('Potential hardcoded salt in bcrypt hash');
  }
  if (/password\s*=\s*['"`](.*)['"`]/.test(code)) {
    vulnerabilities.Authentication.push('Potential hardcoded password');
  }
  if (/\/auth\/login/.test(code) && !/rateLimit/.test(code)) {
    vulnerabilities.Authentication.push('No rate limiting on login endpoint');
  }
  if (/\bpassword\b/.test(code) && !/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])/.test(code)) {
    vulnerabilities.Authentication.push('Weak password policy');
  }
  if (/location\.search\s*=\s*['"`](.*)['"`]/.test(code)) {
    vulnerabilities.Authentication.push('Sensitive data in URL');
  }

  return {
    XSS: {
      vulnerable: totalRules.XSS > 0 ? (vulnerabilities.XSS.length / totalRules.XSS) * 100 : 0,
      issues: vulnerabilities.XSS
    },
    CodeInjection: {
      vulnerable: totalRules.CodeInjection > 0 ? (vulnerabilities.CodeInjection.length / totalRules.CodeInjection) * 100 : 0,
      issues: vulnerabilities.CodeInjection
    },
    SQLInjection: {
      vulnerable: totalRules.SQLInjection > 0 ? (vulnerabilities.SQLInjection.length / totalRules.SQLInjection) * 100 : 0,
      issues: vulnerabilities.SQLInjection
    },
    Authentication: {
      vulnerable: totalRules.Authentication > 0 ? (vulnerabilities.Authentication.length / totalRules.Authentication) * 100 : 0,
      issues: vulnerabilities.Authentication
    }
  };
}

// Auth Routes
app.post('/api/auth/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const [existingUsers] = await pool.execute('SELECT * FROM users WHERE username = ? OR email = ?', [username, email]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashedPassword]
    );
    res.status(201).json({ message: 'User created successfully', id: result.insertId });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'An error occurred during signup' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
    const user = rows[0];

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'An error occurred during login' });
  }
});

// New route for changing password
app.post('/api/auth/change-password', async (req, res) => {
  const { username, currentPassword, newPassword } = req.body;

  if (!username || !currentPassword || !newPassword) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
    const user = rows[0];

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await pool.execute('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, user.id]);

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ message: 'An error occurred while changing the password' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
