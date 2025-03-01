import { Hono } from 'hono';
import { cors } from 'hono/cors';

const app = new Hono();

// CORS Middleware
app.use('*', cors({
    origin: '*', // Allow all origins (or specify your frontend URL, e.g., 'https://your-frontend.com')
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], // Allowed HTTP methods
    allowHeaders: ['Content-Type', 'Authorization'], // Allowed headers
    exposeHeaders: ['Content-Length'], // Headers exposed to the client
    credentials: true, // Allow credentials (e.g., cookies, authorization headers)
    maxAge: 86400, // Cache CORS preflight response for 1 day
}));

// Helper function to validate request body
const validateRequestBody = async (request) => {
    const contentType = request.headers.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
        return [null, 'Invalid content type'];
    }

    try {
        const body = await request.json();
        return [body, null];
    } catch (error) {
        return [null, 'Invalid JSON body'];
    }
};

// Helper function to hash passwords using Web Crypto API
const hashPassword = async (password) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
};

// Middleware to check if the user is logged in
const authMiddleware = async (c, next) => {
    const sessionToken = c.req.header('Authorization')?.split(' ')[1]; // Bearer <token>
    if (!sessionToken) {
        return c.json({ error: 'Unauthorized' }, 401);
    }

    // Check if the session token exists in the database
    const session = await c.env.DB.prepare(
        'SELECT user_id FROM sessions WHERE session_id = ?'
    ).bind(sessionToken).first();

    if (!session) {
        return c.json({ error: 'Unauthorized' }, 401);
    }

    // Attach the user ID to the context for use in subsequent handlers
    c.set('userId', session.user_id);
    await next();
};

// Registration endpoint
app.post('/register', async (c) => {
    const [body, error] = await validateRequestBody(c.req.raw);
    if (error) return c.json({ error }, 400);

    try {
        // Check if user already exists
        const existingUser = await c.env.DB.prepare(
            'SELECT username FROM users WHERE username = ?'
        ).bind(body.username).first();

        if (existingUser) {
            return c.json({ error: 'Username already exists' }, 409);
        }

        // Hash password
        const hashedPassword = await hashPassword(body.password);

        // Create new user
        const result = await c.env.DB.prepare(
            'INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)'
        ).bind(body.username, hashedPassword, new Date().toISOString()).run();

        if (result.success) {
            return c.json({ message: 'User registered successfully' }, 201);
        }

        return c.json({ error: 'Failed to create user' }, 500);
    } catch (err) {
        return c.json({ error: 'Server error' }, 500);
    }
});

// Login endpoint
app.post('/login', async (c) => {
    const [body, error] = await validateRequestBody(c.req.raw);
    if (error) return c.json({ error }, 400);

    try {
        // Get user from database
        const user = await c.env.DB.prepare(
            'SELECT * FROM users WHERE username = ?'
        ).bind(body.username).first();

        if (!user) {
            return c.json({ error: 'Invalid credentials' }, 401);
        }

        // Compare passwords
        const hashedPassword = await hashPassword(body.password);
        if (hashedPassword !== user.password) {
            return c.json({ error: 'Invalid credentials' }, 401);
        }

        // Generate session token
        const sessionToken = crypto.randomUUID();

        // Store session token in the database
        await c.env.DB.prepare(
            'INSERT INTO sessions (session_id, user_id, created_at) VALUES (?, ?, ?)'
        ).bind(sessionToken, user.id, new Date().toISOString()).run();

        return c.json({
            message: 'Login successful',
            username: user.username,
            sessionToken
        });
    } catch (err) {
        return c.json({ error: 'Server error' }, 500);
    }
});

// Logout endpoint
app.post('/logout', authMiddleware, async (c) => {
    const sessionToken = c.req.header('Authorization')?.split(' ')[1];

    try {
        // Delete the session token from the database
        await c.env.DB.prepare(
            'DELETE FROM sessions WHERE session_id = ?'
        ).bind(sessionToken).run();

        return c.json({ message: 'Logout successful' });
    } catch (err) {
        return c.json({ error: 'Server error' }, 500);
    }
});

// Create a transaction (only for logged-in users)
app.post('/transactions', authMiddleware, async (c) => {
    const [body, error] = await validateRequestBody(c.req.raw);
    if (error) return c.json({ error }, 400);

    // Validate transaction data
    if (!body.description || !body.payees) {
        return c.json({ error: 'Missing required fields' }, 400);
    }

    if (!Array.isArray(body.payees) || body.payees.length === 0) {
        return c.json({ error: 'Payees must be a non-empty array' }, 400);
    }

    // Validate transaction type (default to 'regular' if not provided)
    const transactionType = body.type || 'regular';

    try {
        // Get the logged-in user's ID from the context
        const creditorId = c.get('userId');

        // Check if all payees exist in the database
        for (const payee of body.payees) {
            const payeeExists = await c.env.DB.prepare(
                'SELECT id FROM users WHERE id = ?'
            ).bind(payee.payee_id).first();

            if (!payeeExists) {
                return c.json({ error: `Payee with ID ${payee.payee_id} does not exist` }, 400);
            }
        }

        // Generate a transaction ID
        const txId = crypto.randomUUID();

        // Insert transaction into the database (without amount)
        const txResult = await c.env.DB.prepare(
            'INSERT INTO transactions (tx_id, creditor_id, description, type, created_at) VALUES (?, ?, ?, ?, ?)'
        ).bind(txId, creditorId, body.description, transactionType, new Date().toISOString()).run();

        if (!txResult.success) {
            return c.json({ error: 'Failed to create transaction' }, 500);
        }

        // Insert payees into the database
        for (const payee of body.payees) {
            if (!payee.payee_id || !payee.share) {
                return c.json({ error: 'Invalid payee data' }, 400);
            }

            const payeeResult = await c.env.DB.prepare(
                'INSERT INTO payees (tx_id, payee_id, share) VALUES (?, ?, ?)'
            ).bind(txId, payee.payee_id, payee.share).run();

            if (!payeeResult.success) {
                return c.json({ error: 'Failed to add payee' }, 500);
            }
        }

        return c.json({ message: 'Transaction created successfully', tx_id: txId }, 201);
    } catch (err) {
        return c.json({ error: 'Server error' }, 500);
    }
});

// Get transaction details by ID
app.get('/transactions/:tx_id', authMiddleware, async (c) => {
    const txId = c.req.param('tx_id');

    try {
        // Get transaction details
        const transaction = await c.env.DB.prepare(
            'SELECT * FROM transactions WHERE tx_id = ?'
        ).bind(txId).first();

        if (!transaction) {
            return c.json({ error: 'Transaction not found' }, 404);
        }

        // Get payees for the transaction
        const payees = await c.env.DB.prepare(
            `SELECT p.payee_id, p.share, u.username FROM payees p
            JOIN users u ON p.payee_id = u.id WHERE p.tx_id = ?`
        ).bind(txId).all();

        return c.json({
            tx_id: transaction.tx_id,
            creditor_id: transaction.creditor_id,
            description: transaction.description,
            type: transaction.type,
            created_at: transaction.created_at,
            payees: payees.results
        });
    } catch (err) {
        return c.json({ error: 'Server error' }, 500);
    }
});

// Delete a transaction (only for logged-in users)
app.delete('/transactions/:tx_id', authMiddleware, async (c) => {
    const txId = c.req.param('tx_id');

    try {
        // Check if the user is the creditor of the transaction
        const transaction = await c.env.DB.prepare(
            'SELECT creditor_id FROM transactions WHERE tx_id = ?'
        ).bind(txId).first();

        if (!transaction) {
            return c.json({ error: 'Transaction not found' }, 404);
        }

        const userId = c.get('userId');
        if (transaction.creditor_id !== userId) {
            return c.json({ error: 'You are not authorized to delete this transaction' }, 403);
        }
        
        // Delete payees associated with the transaction
        await c.env.DB.prepare(
            'DELETE FROM payees WHERE tx_id = ?'
        ).bind(txId).run();

        // Delete the transaction
        const result = await c.env.DB.prepare(
            'DELETE FROM transactions WHERE tx_id = ?'
        ).bind(txId).run();

        if (result.success) {
            return c.json({ message: 'Transaction deleted successfully' });
        }

        return c.json({ error: 'Failed to delete transaction' }, 500);
    } catch (err) {
        return c.json({ error: 'Server error' }, 500);
    }
});

// Add a user as a known person (undirected relationship)
app.post('/known-persons', authMiddleware, async (c) => {
    const [body, error] = await validateRequestBody(c.req.raw);
    if (error) return c.json({ error }, 400);

    if (!body.known_user_id) {
        return c.json({ error: 'Missing known_user_id' }, 400);
    }

    try {
        const userId = c.get('userId');
        const knownUserId = body.known_user_id;

        // Check if the known user exists
        const knownUserExists = await c.env.DB.prepare(
            'SELECT id FROM users WHERE id = ?'
        ).bind(knownUserId).first();

        if (!knownUserExists) {
            return c.json({ error: 'Known user does not exist' }, 400);
        }

        // Insert the undirected relationship
        await c.env.DB.prepare(
            'INSERT INTO known_persons (user_id, known_user_id) VALUES (?, ?), (?, ?)'
        ).bind(userId, knownUserId, knownUserId, userId).run();

        return c.json({ message: 'User added as known person successfully' }, 201);
    } catch (err) {
        return c.json({ error: 'Server error' }, 500);
    }
});

// Get all users known by the authorized user
app.get('/known-persons', authMiddleware, async (c) => {
    const userId = c.get('userId');

    try {
        const knownPersons = await c.env.DB.prepare(
            `SELECT u.id, u.username
            FROM known_persons kp
            JOIN users u ON u.id = kp.known_user_id
            WHERE kp.user_id = ?
            
            UNION
            
            SELECT u.id, u.username
            FROM known_persons kp
            JOIN users u ON u.id = kp.user_id
            WHERE kp.known_user_id = ?`
        ).bind(userId,userId).all();

        return c.json({ known_persons: knownPersons.results });
    } catch (err) {
        return c.json({ error: 'Server error' }, 501);
    }
});

// Get all transactions for the authorized user (as creditor or payee)
app.get('/transactions', authMiddleware, async (c) => {
    const userId = c.get('userId');

    try {
        // Get transactions where the user is the creditor
        const creditorTransactions = await c.env.DB.prepare(
            `SELECT 
                t.*, 
                json_group_array(
                    json_object(
                        'payee_id', p.payee_id, 
                        'share', p.share, 
                        'username', u.username
                    )
                ) AS payees
            FROM 
                transactions t
            LEFT JOIN 
                payees p ON t.tx_id = p.tx_id
            LEFT JOIN 
                users u ON p.payee_id = u.id
            WHERE 
                t.creditor_id = ?
            GROUP BY 
                t.tx_id;
            `
        ).bind(userId).all();

        // Get transactions where the user is a payee
        const payeeTransactions = await c.env.DB.prepare(
            `SELECT 
                t.*, 
                json_group_array(
                    json_object(
                        'payee_id', p.payee_id, 
                        'share', p.share, 
                        'username', u.username
                    )
                ) AS payees,
                creditor_user.username AS creditor_username
            FROM 
                transactions t
            JOIN 
                payees p ON t.tx_id = p.tx_id
            JOIN 
                users u ON p.payee_id = u.id
            JOIN 
                users creditor_user ON t.creditor_id = creditor_user.id
            WHERE 
                p.payee_id = ?
            GROUP BY 
                t.tx_id;
            `
        ).bind(userId).all();

        // Parse the payees JSON string into an array
        const parsePayees = (transactions) => {
            return transactions.results.map((tx) => ({
                ...tx,
                payees: JSON.parse(tx.payees)
            }));
        };

        return c.json({
            creditor_transactions: parsePayees(creditorTransactions),
            payee_transactions: parsePayees(payeeTransactions)
        });
    } catch (err) {
        return c.json({ error: 'Server error' }, 500);
    }
});

// Search users by username
app.get('/search-users', authMiddleware, async (c) => {
    const username = c.req.query('username');

    if (!username) {
        return c.json({ error: 'Username query parameter is required' }, 400);
    }

    try {
        const users = await c.env.DB.prepare(
            'SELECT id, username FROM users WHERE username LIKE ? LIMIT 10'
        ).bind(`%${username}%`).all();

        return c.json({ users: users.results });
    } catch (err) {
        return c.json({ error: 'Server error' }, 500);
    }
});

// Get user details by ID
app.get('/users/:userId', authMiddleware, async (c) => {
    const userId = c.req.param('userId');

    try {
        const user = await c.env.DB.prepare(
            'SELECT id, username, created_at FROM users WHERE id = ?'
        ).bind(userId).first();

        if (!user) {
            return c.json({ error: 'User not found' }, 404);
        }

        return c.json({
            id: user.id,
            username: user.username,
            created_at: user.created_at
        });
    } catch (err) {
        return c.json({ error: 'Server error' }, 500);
    }
});

// Get current user details based on session token
app.get('/me', authMiddleware, async (c) => {
    const userId = c.get('userId'); // Get the user ID from the context

    try {
        // Fetch user details from the database
        const user = await c.env.DB.prepare(
            'SELECT id, username FROM users WHERE id = ?'
        ).bind(userId).first();

        if (!user) {
            return c.json({ error: 'User not found' }, 404);
        }

        return c.json({
            id: user.id,
            username: user.username
        });
    } catch (err) {
        return c.json({ error: 'Server error' }, 500);
    }
});

export default app;