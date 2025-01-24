import { Hono } from 'hono';

const app = new Hono();

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
    if (!body.amount || !body.description || !body.payees) {
        return c.json({ error: 'Missing required fields' }, 400);
    }

    if (!Array.isArray(body.payees) || body.payees.length === 0) {
        return c.json({ error: 'Payees must be a non-empty array' }, 400);
    }

    try {
        // Get the logged-in user's ID from the context
        const creditorId = c.get('userId');

        // Generate a transaction ID
        const txId = crypto.randomUUID();

        // Insert transaction into the database
        const txResult = await c.env.DB.prepare(
            'INSERT INTO transactions (tx_id, creditor_id, amount, description, created_at) VALUES (?, ?, ?, ?, ?)'
        ).bind(txId, creditorId, body.amount, body.description, new Date().toISOString()).run();

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

// Delete a transaction (only for logged-in users)
app.delete('/transactions/:tx_id', authMiddleware, async (c) => {
    const txId = c.req.param('tx_id');

    try {
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

export default app;