
import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';

interface UserInfo {
  sub: string;
  username: string;
}

export default function Resource() {
  const [resourceData, setResourceData] = useState<string | null>(null);
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    const accessToken = sessionStorage.getItem('accessToken');
    const idToken = sessionStorage.getItem('idToken');

    if (!accessToken || !idToken) {
      console.log('No tokens found, redirecting to login.');
      router.push('/login');
      return;
    }

    // Decode ID Token (for display purposes)
    try {
      const parts = idToken.split('.');
      if (parts.length === 3) {
        const decodedPayload = JSON.parse(atob(parts[1]));
        setUserInfo({
          sub: decodedPayload.sub,
          username: decodedPayload.username || decodedPayload.sub, // Fallback to sub if username not present
        });
      } else {
        setError('Invalid ID token format.');
      }
    } catch (e) {
      setError('Failed to decode ID token.');
      console.error('ID Token decode error:', e);
    }

    // Fetch protected resource
    fetch('https://localhost:8080/api/resource', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })
      .then((res) => {
        if (res.status === 401) {
          console.log('Unauthorized to access resource, redirecting to login.');
          router.push('/login');
          return;
        }
        return res.json();
      })
      .then((data) => {
        if (data && data.data) {
          setResourceData(data.data);
        } else if (data) {
          setError(data.error || 'Failed to fetch resource.');
        }
      })
      .catch((err) => {
        setError(err.message || 'Network error fetching resource.');
        console.error('Resource fetch error:', err);
      });

  }, []);

  const handleLogout = () => {
    sessionStorage.removeItem('accessToken');
    sessionStorage.removeItem('idToken');
    // Optionally, call backend logout endpoint if there were server-side sessions
    fetch('https://localhost:8080/logout', { method: 'POST' })
      .then(() => {
        console.log('Logged out from backend (if applicable).');
        router.push('/login');
      })
      .catch((err) => {
        console.error('Error during backend logout:', err);
        router.push('/login'); // Still redirect even if backend logout fails
      });
  };

  return (
    <div className="container mx-auto p-4">
      <h2 className="text-xl font-bold mb-2">Protected Resource Page</h2>

      {error && <p className="text-red-500">Error: {error}</p>}

      {userInfo && (
        <div className="mb-4 p-4 border rounded">
          <h3 className="text-lg font-bold">User Information (from ID Token)</h3>
          <p><strong>Subject (sub):</strong> {userInfo.sub}</p>
          <p><strong>Username:</strong> {userInfo.username}</p>
        </div>
      )}

      {resourceData && (
        <div className="p-4 border rounded">
          <h3 className="text-lg font-bold">Protected Resource Data</h3>
          <p>{resourceData}</p>
        </div>
      )}

      <button onClick={handleLogout} className="mt-4 bg-red-500 text-white p-2 rounded">
        Logout
      </button>
    </div>
  );
}
