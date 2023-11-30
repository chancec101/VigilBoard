// server.ts
import express, { Request, Response } from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

interface User {
  id: number;
  username: string;
  password: string;
}

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());

const SECRET_KEY = 'your_secret_key';

const users: User[] = [
  // Your user data here
  {
  id: 1,
  username: 'user',
  password: '$2y$10$.uZeYquoNF.dygRQnNAEHedas9lGzHKfjS26sBrD1kQrdyRfwWH4K',
  },
];

// Define a route handler for the root path
app.get('/', (req: Request, res: Response) => {
  res.send('Welcome to the Express server!');
});

// Login endpoint
app.post('/api/login', (req: Request, res: Response) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);

  if (!user) return res.status(401).send('Invalid username or password');

  bcrypt.compare(password, user.password, (err, result) => {
    if (err || !result) return res.status(401).send('Invalid username or password');

    const token = jwt.sign({ username: user.username, id: user.id }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
