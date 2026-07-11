const { verify } = require('../utils/jwt');

function pickToken(req) {
  const h = req.headers.authorization;
  if (h && h.startsWith('Bearer ')) return h.slice(7);
  return null;
}

exports.requireUser = (req, res, next) => {
  try {
    const token = pickToken(req);
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    const payload = verify(token);
    if (payload.role !== 'user') return res.status(403).json({ error: 'Forbidden' });
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

exports.requireAdmin = (req, res, next) => {
  try {
    const token = pickToken(req);
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    const payload = verify(token);
    if (payload.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    req.admin = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired admin token' });
  }
};
