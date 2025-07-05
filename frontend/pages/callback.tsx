
import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';

export default function Callback() {
  const router = useRouter();
  // const [resource, setResource] = useState(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const { code } = router.query;
    const codeVerifier = sessionStorage.getItem('codeVerifier');

    if (code && codeVerifier) {
      const clientID = 'nextjs-client';
      const redirectURI = 'http://localhost:3000/callback';
      const grantType = 'authorization_code';

      const params = new URLSearchParams();
      params.append('grant_type', grantType);
      params.append('code', code as string);
      params.append('redirect_uri', redirectURI);
      params.append('client_id', clientID);
      params.append('code_verifier', codeVerifier);

      console.log('Attempting to exchange code for token...');
      fetch('https://localhost:8080/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params,
      })
        .then((res) => {
          console.log('Token endpoint response status:', res.status);
          return res.json();
        })
        .then((data) => {
          console.log("con co be be", data)
          console.log('Token endpoint response data:', data);
          if (data.access_token && data.id_token) {
            console.log('Access and ID tokens received. Storing and redirecting.');
            sessionStorage.setItem('accessToken', data.access_token);
            sessionStorage.setItem('idToken', data.id_token);
            router.push('/resource');
          } else {
            console.error('Error receiving tokens:', data.error);
            setError(data.error);
          }
        })
        .catch((err) => {
          console.error('Error during token exchange:', err);
          setError(err.message);
        });
    }
  }, [router.query]);

  return (
    <div className="container mx-auto p-4">
      <h2 className="text-xl font-bold mb-2">Processing Login...</h2>
      {error && <p className="text-red-500">Error: {error}</p>}
    </div>
  );
}
