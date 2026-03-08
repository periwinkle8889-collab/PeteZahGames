import rateLimit from 'express-rate-limit';
import { toIPv4, extractToken, verifyToken, updateIPReputation } from './security.js';

export const authLimiter = rateLimit({
  windowMs: 60000,
  max: 60,
  keyGenerator: req => toIPv4(null, req),
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    updateIPReputation(toIPv4(null, req), -5);
    res.status(429).json({ error: 'Too many authentication attempts' });
  }
});

export const signupLimiter = rateLimit({
  windowMs: 3600000,
  max: 3,
  keyGenerator: req => toIPv4(null, req),
  message: 'Too many accounts created from this IP.'
});

export const pfpLimiter = rateLimit({
  windowMs: 3600000,
  max: 5,
  keyGenerator: req => req.session?.user?.id || toIPv4(null, req),
  message: 'Too many profile picture uploads.'
});

export const localStorageLimiter = rateLimit({
  windowMs: 60000,
  max: 10,
  keyGenerator: req => req.session?.user?.id || toIPv4(null, req),
  message: 'Too many saves, slow down.'
});

export function createApiLimiter(shield) {
  return rateLimit({
    windowMs: 15000,
    max: req => {
      const token = extractToken(req);
      return verifyToken(token, req) ? 200 : 60;
    },
    keyGenerator: req => {
      const token = extractToken(req);
      if (verifyToken(token, req)) return `token:${token.slice(0, 16)}`;
      if (req.session?.user?.id) return `user:${req.session.user.id}`;
      return toIPv4(null, req);
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      updateIPReputation(toIPv4(null, req), -3);
      shield.incrementBlocked(toIPv4(null, req), 'rate_limit');
      res.status(429).json({ error: 'Too many requests' });
    }
  });
}

export function createAiLimiter(shield) {
  return rateLimit({
    windowMs: 60000,
    max: 20,
    keyGenerator: req => toIPv4(null, req),
    handler: (req, res) => {
      updateIPReputation(toIPv4(null, req), -3);
      shield.incrementBlocked(toIPv4(null, req), 'ai_rate_limit');
      res.status(429).json({ error: 'Too many AI requests' });
    }
  });
}