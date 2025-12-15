/**
 * =============================================================================
 * FRONTEND - APP.JS avec Authentification Complète
 * =============================================================================
 */

import { useState, useEffect, createContext, useContext } from 'react';
import api from './api/axios';
import { sanitizeInput } from './utils/sanitize';
import './App.css';

// Context pour l'authentification
const AuthContext = createContext(null);

// Hook personnalisé pour l'auth
const useAuth = () => useContext(AuthContext);

// =============================================================================
// COMPOSANT LOGIN
// =============================================================================

function LoginPage({ onLogin, onSwitchToRegister }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await api.post('/auth/login', {
        email: sanitizeInput(email),
        password
      });
      onLogin(response.data.data.user);
    } catch (err) {
      setError(err.response?.data?.error || 'Erreur de connexion');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-box">
        <h2>🔐 Connexion</h2>
        
        {error && <div className="error-message">{error}</div>}
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
            />
          </div>
          
          <div className="form-group">
            <label>Mot de passe</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
            />
          </div>
          
          <button type="submit" disabled={loading} className="btn-primary">
            {loading ? 'Connexion...' : 'Se connecter'}
          </button>
        </form>
        
        <p className="auth-switch">
          Pas encore de compte ?{' '}
          <button onClick={onSwitchToRegister} className="link-button">
            S'inscrire
          </button>
        </p>
      </div>
    </div>
  );
}

// =============================================================================
// COMPOSANT REGISTER
// =============================================================================

function RegisterPage({ onRegister, onSwitchToLogin }) {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [errors, setErrors] = useState([]);
  const [loading, setLoading] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState({ score: 0, label: '' });

  // Validation du mot de passe en temps réel
  const checkPasswordStrength = (password) => {
    let score = 0;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[a-z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score++;

    const labels = ['Très faible', 'Faible', 'Moyen', 'Bon', 'Fort', 'Très fort'];
    setPasswordStrength({
      score,
      label: labels[Math.min(score, 5)]
    });
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    
    if (name === 'password') {
      checkPasswordStrength(value);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrors([]);

    // Validation côté client
    const validationErrors = [];
    
    if (formData.username.length < 3) {
      validationErrors.push('Le username doit faire au moins 3 caractères');
    }
    if (!/^[a-zA-Z0-9]+$/.test(formData.username)) {
      validationErrors.push('Le username ne peut contenir que des lettres et chiffres');
    }
    if (formData.password.length < 12) {
      validationErrors.push('Le mot de passe doit faire au moins 12 caractères');
    }
    if (formData.password !== formData.confirmPassword) {
      validationErrors.push('Les mots de passe ne correspondent pas');
    }

    if (validationErrors.length > 0) {
      setErrors(validationErrors);
      return;
    }

    setLoading(true);

    try {
      const response = await api.post('/auth/register', {
        username: sanitizeInput(formData.username),
        email: sanitizeInput(formData.email),
        password: formData.password
      });
      onRegister(response.data.data.user);
    } catch (err) {
      const serverErrors = err.response?.data?.errors || [{ message: err.response?.data?.error || 'Erreur' }];
      setErrors(serverErrors.map(e => e.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-box">
        <h2>📝 Inscription</h2>
        
        {errors.length > 0 && (
          <div className="error-message">
            {errors.map((err, i) => <p key={i}>{err}</p>)}
          </div>
        )}
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Nom d'utilisateur</label>
            <input
              type="text"
              name="username"
              value={formData.username}
              onChange={handleChange}
              required
              minLength={3}
              maxLength={50}
              pattern="[a-zA-Z0-9]+"
            />
          </div>
          
          <div className="form-group">
            <label>Email</label>
            <input
              type="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              required
            />
          </div>
          
          <div className="form-group">
            <label>Mot de passe (min. 12 caractères)</label>
            <input
              type="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              required
              minLength={12}
            />
            {formData.password && (
              <div className={`password-strength strength-${passwordStrength.score}`}>
                Force: {passwordStrength.label}
              </div>
            )}
          </div>
          
          <div className="form-group">
            <label>Confirmer le mot de passe</label>
            <input
              type="password"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleChange}
              required
            />
          </div>
          
          <button type="submit" disabled={loading} className="btn-primary">
            {loading ? 'Inscription...' : 'S\'inscrire'}
          </button>
        </form>
        
        <p className="auth-switch">
          Déjà un compte ?{' '}
          <button onClick={onSwitchToLogin} className="link-button">
            Se connecter
          </button>
        </p>
      </div>
    </div>
  );
}

// =============================================================================
// COMPOSANT DASHBOARD
// =============================================================================

function Dashboard({ user, onLogout }) {
  const [users, setUsers] = useState([]);
  const [comments, setComments] = useState([]);
  const [newComment, setNewComment] = useState('');
  const [loading, setLoading] = useState(false);
  const [csrfToken, setCsrfToken] = useState('');

  useEffect(() => {
    loadData();
    fetchCsrfToken();
  }, []);

  const fetchCsrfToken = async () => {
    try {
      const response = await api.get('/csrf-token');
      setCsrfToken(response.data.csrfToken);
    } catch (err) {
      console.error('Erreur CSRF:', err);
    }
  };

  const loadData = async () => {
    try {
      const [usersRes, commentsRes] = await Promise.all([
        api.get('/users'),
        api.get('/comments')
      ]);
      setUsers(usersRes.data.data.users || []);
      setComments(commentsRes.data.data.comments || []);
    } catch (err) {
      console.error('Erreur:', err);
    }
  };

  const handleComment = async (e) => {
    e.preventDefault();
    if (!newComment.trim()) return;

    setLoading(true);
    try {
      await api.post('/comments', 
        { content: sanitizeInput(newComment) },
        { headers: { 'X-CSRF-Token': csrfToken } }
      );
      setNewComment('');
      loadData();
      fetchCsrfToken(); // Nouveau token après action
    } catch (err) {
      console.error('Erreur:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await api.post('/auth/logout', {}, {
        headers: { 'X-CSRF-Token': csrfToken }
      });
    } catch (err) {
      console.error('Erreur logout:', err);
    }
    onLogout();
  };

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>🔐 IPSSI Secure App</h1>
        <div className="user-info">
          <span>👤 {user.username} ({user.role})</span>
          <button onClick={handleLogout} className="btn-logout">Déconnexion</button>
        </div>
      </header>

      <main className="dashboard-content">
        <section className="section">
          <h2>👥 Utilisateurs ({users.length})</h2>
          <div className="users-grid">
            {users.map(u => (
              <div key={u.id} className="user-card">
                <strong>{u.username}</strong>
                <span>{u.email}</span>
                <span className={`role-badge role-${u.role}`}>{u.role}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="section">
          <h2>💬 Commentaires</h2>
          
          <form onSubmit={handleComment} className="comment-form">
            <textarea
              value={newComment}
              onChange={(e) => setNewComment(e.target.value)}
              placeholder="Écrivez un commentaire..."
              maxLength={1000}
              required
            />
            <button type="submit" disabled={loading} className="btn-primary">
              {loading ? 'Envoi...' : 'Publier'}
            </button>
          </form>

          <div className="comments-list">
            {comments.map(c => (
              <div key={c.id} className="comment-card">
                <div className="comment-header">
                  <strong>{c.author?.username || 'Anonyme'}</strong>
                  <span>{new Date(c.createdAt).toLocaleDateString('fr-FR')}</span>
                </div>
                <p>{c.content}</p>
              </div>
            ))}
          </div>
        </section>
      </main>

      <footer className="dashboard-footer">
        🔐 Sécurisé avec Argon2id + OWASP Best Practices
      </footer>
    </div>
  );
}

// =============================================================================
// COMPOSANT PRINCIPAL
// =============================================================================

function App() {
  const [user, setUser] = useState(null);
  const [view, setView] = useState('login'); // 'login', 'register', 'dashboard'
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const response = await api.get('/auth/me');
      setUser(response.data.data.user);
      setView('dashboard');
    } catch (err) {
      // Non authentifié
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = (userData) => {
    setUser(userData);
    setView('dashboard');
  };

  const handleLogout = () => {
    setUser(null);
    setView('login');
  };

  if (loading) {
    return <div className="loading">Chargement...</div>;
  }

  return (
    <AuthContext.Provider value={{ user, setUser }}>
      {view === 'login' && (
        <LoginPage 
          onLogin={handleLogin} 
          onSwitchToRegister={() => setView('register')} 
        />
      )}
      {view === 'register' && (
        <RegisterPage 
          onRegister={handleLogin}
          onSwitchToLogin={() => setView('login')} 
        />
      )}
      {view === 'dashboard' && user && (
        <Dashboard user={user} onLogout={handleLogout} />
      )}
    </AuthContext.Provider>
  );
}

export default App;
