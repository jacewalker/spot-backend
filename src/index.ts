import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'spot-dev-secret-key';

// Middleware
app.use(cors());
app.use(helmet());
app.use(compression());
app.use(express.json());

// Root route
app.get('/', (req: Request, res: Response) => {
  res.json({
    name: 'Spot API',
    version: '1.0.0',
    status: 'running',
    endpoints: {
      health: '/api/health',
      auth: '/api/auth/login, /api/auth/signup',
      feed: '/api/feed',
      workouts: '/api/workouts',
      segments: '/api/segments/near',
      users: '/api/users/me',
    },
  });
});

// In-memory storage (for demo - use a real database in production)
interface User {
  id: string;
  email: string;
  password: string;
  display_name: string;
  suburb?: string;
  premium: boolean;
  avatar_url?: string;
  created_at: string;
  apple_user_id?: string;
}

// WorkoutReference: Only stores summary data for social features
// Full workout data is stored in user's HealthKit (privacy-first architecture)
interface WorkoutReference {
  id: string;
  user_id: string;
  visibility: 'public' | 'friends' | 'private';
  summary: {
    duration_seconds: number;
    exercise_count: number;
    exercise_names: string[];
  };
  created_at: string;
  likes_count: number;
  comments_count: number;
}

const users: Map<string, User> = new Map();
const workouts: Map<string, WorkoutReference> = new Map();
const likes: Map<string, Set<string>> = new Map(); // workoutId -> Set of userIds
const follows: Map<string, Set<string>> = new Map(); // userId -> Set of followingIds
const appleUsers: Map<string, string> = new Map(); // appleUserId -> userId

// Auth middleware
interface AuthRequest extends Request {
  user?: { id: string; email: string };
}

const authenticate = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const token = authHeader.substring(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { id: string; email: string };
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Helper to get user response (without password)
const getUserResponse = (user: User) => ({
  id: user.id,
  email: user.email,
  display_name: user.display_name,
  suburb: user.suburb,
  premium: user.premium,
  avatar_url: user.avatar_url,
  created_at: user.created_at,
});

// ======================== AUTH ROUTES ========================

app.post('/api/auth/signup', async (req: Request, res: Response) => {
  try {
    const { email, password, display_name } = req.body;

    if (!email || !password || !display_name) {
      return res.status(400).json({ message: 'Email, password, and display name are required' });
    }

    // Check if user exists
    for (const user of users.values()) {
      if (user.email === email) {
        return res.status(400).json({ message: 'Email already registered' });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const user: User = {
      id,
      email,
      password: hashedPassword,
      display_name,
      premium: false,
      created_at: new Date().toISOString(),
    };

    users.set(id, user);

    const token = jwt.sign({ id, email }, JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({
      token,
      user: getUserResponse(user),
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    // Find user by email
    let foundUser: User | undefined;
    for (const user of users.values()) {
      if (user.email === email) {
        foundUser = user;
        break;
      }
    }

    // For demo: create user if not exists
    if (!foundUser) {
      const hashedPassword = await bcrypt.hash(password, 10);
      const id = uuidv4();
      foundUser = {
        id,
        email,
        password: hashedPassword,
        display_name: email.split('@')[0],
        premium: false,
        created_at: new Date().toISOString(),
      };
      users.set(id, foundUser);
    }

    // Verify password (skip for demo auto-creation)
    const isValidPassword = await bcrypt.compare(password, foundUser.password);
    if (!isValidPassword && users.size > 1) {
      // Only check password if not just created
      // For demo: always allow login
    }

    const token = jwt.sign({ id: foundUser.id, email: foundUser.email }, JWT_SECRET, {
      expiresIn: '30d',
    });

    res.json({
      token,
      user: getUserResponse(foundUser),
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/apple', async (req: Request, res: Response) => {
  try {
    const { identity_token, user: appleUserId, full_name } = req.body;

    if (!identity_token) {
      return res.status(400).json({ message: 'Identity token is required' });
    }

    // Decode the identity token to get email (in production, verify with Apple's public keys)
    let email: string | undefined;
    try {
      const tokenParts = identity_token.split('.');
      if (tokenParts.length === 3) {
        const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
        email = payload.email;
      }
    } catch (e) {
      console.error('Error decoding Apple identity token:', e);
    }

    // Check if we already have a user with this Apple ID
    let userId = appleUserId ? appleUsers.get(appleUserId) : undefined;
    let foundUser: User | undefined;

    if (userId) {
      foundUser = users.get(userId);
    }

    // If no existing Apple user, check by email
    if (!foundUser && email) {
      for (const user of users.values()) {
        if (user.email === email) {
          foundUser = user;
          // Link Apple ID to existing account
          if (appleUserId) {
            foundUser.apple_user_id = appleUserId;
            users.set(foundUser.id, foundUser);
            appleUsers.set(appleUserId, foundUser.id);
          }
          break;
        }
      }
    }

    // Create new user if not found
    if (!foundUser) {
      const id = uuidv4();
      const displayName = full_name?.givenName && full_name?.familyName
        ? `${full_name.givenName} ${full_name.familyName}`
        : full_name?.givenName || email?.split('@')[0] || 'Apple User';

      foundUser = {
        id,
        email: email || `apple_${appleUserId || id}@privaterelay.appleid.com`,
        password: '', // No password for Apple Sign In users
        display_name: displayName,
        premium: false,
        created_at: new Date().toISOString(),
        apple_user_id: appleUserId,
      };

      users.set(id, foundUser);
      if (appleUserId) {
        appleUsers.set(appleUserId, id);
      }
    }

    const token = jwt.sign({ id: foundUser.id, email: foundUser.email }, JWT_SECRET, {
      expiresIn: '30d',
    });

    res.json({
      token,
      user: getUserResponse(foundUser),
    });
  } catch (error) {
    console.error('Apple auth error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ======================== FEED ROUTES ========================

app.get('/api/feed', authenticate, (req: AuthRequest, res: Response) => {
  const cursor = req.query.cursor as string | undefined;
  const limit = 20;

  // Get all public workouts sorted by created_at desc
  const allWorkouts = Array.from(workouts.values())
    .filter((w) => w.visibility === 'public')
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  let startIndex = 0;
  if (cursor) {
    startIndex = allWorkouts.findIndex((w) => w.id === cursor) + 1;
  }

  const paginatedWorkouts = allWorkouts.slice(startIndex, startIndex + limit);
  const nextCursor = paginatedWorkouts.length === limit ? paginatedWorkouts[paginatedWorkouts.length - 1]?.id : undefined;

  // Add like status and user info for display
  const workoutsWithLikes = paginatedWorkouts.map((w) => {
    const owner = users.get(w.user_id);
    return {
      ...w,
      display_name: owner?.display_name || 'Unknown',
      avatar_url: owner?.avatar_url,
      liked_by_user: likes.get(w.id)?.has(req.user!.id) || false,
    };
  });

  res.json({
    workouts: workoutsWithLikes,
    next_cursor: nextCursor,
    has_more: !!nextCursor,
  });
});

// ======================== WORKOUT ROUTES ========================

app.post('/api/workouts', authenticate, (req: AuthRequest, res: Response) => {
  const user = users.get(req.user!.id);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  // Only accept summary data - full workout is stored in HealthKit
  const { visibility, summary } = req.body;

  if (!summary || typeof summary.duration_seconds !== 'number' || typeof summary.exercise_count !== 'number') {
    return res.status(400).json({ message: 'Summary with duration_seconds and exercise_count required' });
  }

  const workoutRef: WorkoutReference = {
    id: uuidv4(),
    user_id: req.user!.id,
    visibility: visibility || 'public',
    summary: {
      duration_seconds: summary.duration_seconds,
      exercise_count: summary.exercise_count,
      exercise_names: summary.exercise_names || [],
    },
    created_at: new Date().toISOString(),
    likes_count: 0,
    comments_count: 0,
  };

  workouts.set(workoutRef.id, workoutRef);

  // Return with user info for display
  res.status(201).json({
    ...workoutRef,
    display_name: user.display_name,
    avatar_url: user.avatar_url,
  });
});

app.get('/api/workouts/:id', authenticate, (req: AuthRequest, res: Response) => {
  const workout = workouts.get(req.params.id);
  if (!workout) {
    return res.status(404).json({ message: 'Workout not found' });
  }

  const owner = users.get(workout.user_id);

  res.json({
    ...workout,
    display_name: owner?.display_name || 'Unknown',
    avatar_url: owner?.avatar_url,
    liked_by_user: likes.get(workout.id)?.has(req.user!.id) || false,
  });
});

app.patch('/api/workouts/:id', authenticate, (req: AuthRequest, res: Response) => {
  const workout = workouts.get(req.params.id);
  if (!workout) {
    return res.status(404).json({ message: 'Workout not found' });
  }

  if (workout.user_id !== req.user!.id) {
    return res.status(403).json({ message: 'Forbidden' });
  }

  // Only allow updating visibility (summary comes from HealthKit)
  const { visibility } = req.body;
  if (visibility && ['public', 'friends', 'private'].includes(visibility)) {
    workout.visibility = visibility;
  }

  workouts.set(workout.id, workout);

  const owner = users.get(workout.user_id);
  res.json({
    ...workout,
    display_name: owner?.display_name || 'Unknown',
    avatar_url: owner?.avatar_url,
  });
});

app.delete('/api/workouts/:id', authenticate, (req: AuthRequest, res: Response) => {
  const workout = workouts.get(req.params.id);
  if (!workout) {
    return res.status(404).json({ message: 'Workout not found' });
  }

  if (workout.user_id !== req.user!.id) {
    return res.status(403).json({ message: 'Forbidden' });
  }

  workouts.delete(req.params.id);
  res.status(204).send();
});

app.post('/api/workouts/:id/like', authenticate, (req: AuthRequest, res: Response) => {
  const workout = workouts.get(req.params.id);
  if (!workout) {
    return res.status(404).json({ message: 'Workout not found' });
  }

  if (!likes.has(workout.id)) {
    likes.set(workout.id, new Set());
  }

  const workoutLikes = likes.get(workout.id)!;
  if (!workoutLikes.has(req.user!.id)) {
    workoutLikes.add(req.user!.id);
    workout.likes_count++;
    workouts.set(workout.id, workout);
  }

  res.status(204).send();
});

app.delete('/api/workouts/:id/like', authenticate, (req: AuthRequest, res: Response) => {
  const workout = workouts.get(req.params.id);
  if (!workout) {
    return res.status(404).json({ message: 'Workout not found' });
  }

  const workoutLikes = likes.get(workout.id);
  if (workoutLikes?.has(req.user!.id)) {
    workoutLikes.delete(req.user!.id);
    workout.likes_count--;
    workouts.set(workout.id, workout);
  }

  res.status(204).send();
});

// ======================== USER ROUTES ========================

app.get('/api/users/me', authenticate, (req: AuthRequest, res: Response) => {
  const user = users.get(req.user!.id);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  res.json(getUserResponse(user));
});

app.patch('/api/users/me', authenticate, (req: AuthRequest, res: Response) => {
  const user = users.get(req.user!.id);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  const { display_name, suburb, avatar_url } = req.body;
  if (display_name) user.display_name = display_name;
  if (suburb !== undefined) user.suburb = suburb;
  if (avatar_url !== undefined) user.avatar_url = avatar_url;

  users.set(user.id, user);

  res.json(getUserResponse(user));
});

app.get('/api/users/:id', authenticate, (req: AuthRequest, res: Response) => {
  const user = users.get(req.params.id);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  res.json(getUserResponse(user));
});

app.get('/api/users/:id/workouts', authenticate, (req: AuthRequest, res: Response) => {
  const targetUser = users.get(req.params.id);
  const isOwnProfile = req.params.id === req.user!.id;
  const isFollowing = follows.get(req.user!.id)?.has(req.params.id) || false;

  // Filter workouts based on visibility
  const userWorkouts = Array.from(workouts.values())
    .filter((w) => {
      if (w.user_id !== req.params.id) return false;
      if (isOwnProfile) return true; // Show all own workouts
      if (w.visibility === 'public') return true;
      if (w.visibility === 'friends' && isFollowing) return true;
      return false;
    })
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .map((w) => ({
      ...w,
      display_name: targetUser?.display_name || 'Unknown',
      avatar_url: targetUser?.avatar_url,
      liked_by_user: likes.get(w.id)?.has(req.user!.id) || false,
    }));

  res.json({
    workouts: userWorkouts,
    has_more: false,
  });
});

// ======================== SOCIAL ROUTES ========================

app.post('/api/users/:id/follow', authenticate, (req: AuthRequest, res: Response) => {
  if (req.params.id === req.user!.id) {
    return res.status(400).json({ message: 'Cannot follow yourself' });
  }

  if (!users.has(req.params.id)) {
    return res.status(404).json({ message: 'User not found' });
  }

  if (!follows.has(req.user!.id)) {
    follows.set(req.user!.id, new Set());
  }

  follows.get(req.user!.id)!.add(req.params.id);
  res.status(204).send();
});

app.delete('/api/users/:id/follow', authenticate, (req: AuthRequest, res: Response) => {
  follows.get(req.user!.id)?.delete(req.params.id);
  res.status(204).send();
});

// ======================== SEGMENTS ROUTES ========================

const mockSegments = [
  {
    id: '1',
    name: 'Downtown Gym - Bench King',
    exercise: 'Bench Press',
    area: { type: 'Polygon', coordinates: [] },
    rule: { type: 'max_weight', exercise: 'Bench Press' },
    current_holder: { user_id: 'user1', display_name: 'Alex J.', metric_value: 120 },
    leaderboard: [],
  },
  {
    id: '2',
    name: 'Fitness First - Squat Master',
    exercise: 'Squat',
    area: { type: 'Polygon', coordinates: [] },
    rule: { type: 'max_weight', exercise: 'Squat' },
    current_holder: { user_id: 'user2', display_name: 'Mike C.', metric_value: 180 },
    leaderboard: [],
  },
];

app.get('/api/segments/near', authenticate, (req: AuthRequest, res: Response) => {
  res.json(mockSegments);
});

app.get('/api/segments/:id', authenticate, (req: AuthRequest, res: Response) => {
  const segment = mockSegments.find((s) => s.id === req.params.id);
  if (!segment) {
    return res.status(404).json({ message: 'Segment not found' });
  }
  res.json(segment);
});

// ======================== HEALTH CHECK ========================
// Note: Health data sync endpoints removed - all health data now stored in HealthKit

app.get('/api/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   🏋️  Spot Backend API Server                              ║
║                                                            ║
║   Server running at: http://localhost:${PORT}               ║
║   API Base URL:      http://localhost:${PORT}/api           ║
║                                                            ║
║   Endpoints:                                               ║
║   POST   /api/auth/login                                   ║
║   POST   /api/auth/signup                                  ║
║   POST   /api/auth/apple                                   ║
║   GET    /api/feed                                         ║
║   POST   /api/workouts                                     ║
║   GET    /api/workouts/:id                                 ║
║   GET    /api/users/me                                     ║
║   GET    /api/segments/near                                ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
  `);
});
