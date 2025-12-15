import axios from 'axios';

// Je passe par Nginx (même origine) par défaut, c'est ce qu'il y a de plus stable en Docker.
const API_BASE = process.env.REACT_APP_API_URL
  ? `${process.env.REACT_APP_API_URL.replace(/\/$/, '')}/api`
  : '/api';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
});

let csrfTokenCache = null;

async function getCsrfToken() {
  // Je ne redemande pas le token si je l'ai déjà.
  if (csrfTokenCache) return csrfTokenCache;

  const response = await api.get('/csrf-token');
  const token = response.data.csrfToken;

  if (!token) {
    // Je préfère échouer explicitement plutôt que d'envoyer des requêtes mutantes sans protection.
    throw new Error('CSRF token introuvable: format de réponse inattendu');
  }

  csrfTokenCache = token;
  return token;
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();
  const isMutating = ['post', 'put', 'patch', 'delete'].includes(method);

  if (isMutating) {
    const csrfToken = await getCsrfToken();
    config.headers = config.headers || {};
    config.headers['X-CSRF-Token'] = csrfToken;
  }

  return config;
}, (error) => Promise.reject(error));

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Je tente un refresh une seule fois si l'access token a expiré.
    if (error.response?.status === 401 && originalRequest && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        await api.post('/auth/refresh');
        csrfTokenCache = null; // Je force un nouveau CSRF token si la session a changé.
        return api(originalRequest);
      } catch (refreshError) {
        csrfTokenCache = null;
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export default api;
