
'use client';

import { useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';

export default function Callback() {
  const searchParams = useSearchParams();
  const [resource, setResource] = useState(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const code = searchParams.get('code');
    const codeVerifier = sessionStorage.getItem('codeVerifier');

    if (code && codeVerifier) {
      const clientID = 'nextjs-client';
      const redirectURI = 'http://localhost:3000/callback';
      const grantType = 'authorization_code';

      const params = new URLSearchParams();
      params.append('grant_type', grantType);
      params.append('code', code);
      params.append('redirect_uri', redirectURI);
      params.append('client_id', clientID);
      params.append('code_verifier', codeVerifier);

      fetch('https://localhost:8080/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params,
      })
        .then((res) => res.json())
        .then((data) => {
          if (data.access_token) {
            sessionStorage.setItem('accessToken', data.access_token);
            fetchResource(data.access_token);
          } else {
            setError(data.error);
          }
        })
        .catch((err) => setError(err.message));
    }
  }, [searchParams]);

  const fetchResource = (accessToken: string) => {
    fetch('https://localhost:8080/api/resource', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.data) {
          setResource(data.data);
        } else {
          setError(data.error);
        }
      })
      .catch((err) => setError(err.message));
  };

  return (
    <div>
      <h2 className="text-xl font-bold mb-2">Callback</h2>
      {error && <p className="text-red-500">Error: {error}</p>}
      {resource && (
        <div>
          <h3 className="text-lg font-bold">Protected Resource:</h3>
          <p>{resource}</p>
        </div>
      )}
    </div>
  );
}
