
import { useRouter } from 'next/router';

export default function Login() {
  const router = useRouter();

  const handleLogin = () => {
    const clientID = 'nextjs-client';
    const redirectURI = 'http://localhost:3000/callback';
    const responseType = 'code';
    const scope = 'openid profile email';
    const codeChallengeMethod = 'S256';

    // Generate code verifier and challenge
    const codeVerifier = generateRandomString(128);
    sessionStorage.setItem('codeVerifier', codeVerifier);

    generateCodeChallenge(codeVerifier).then((codeChallenge) => {
      const authURL = `https://localhost:8080/authorize?response_type=${responseType}&client_id=${clientID}&redirect_uri=${redirectURI}&scope=${scope}&code_challenge=${codeChallenge}&code_challenge_method=${codeChallengeMethod}`;
      router.push(authURL);
    });
  };

  return (
    <div className="container mx-auto p-4">
      <h2 className="text-xl font-bold mb-2">Login</h2>
      <button onClick={handleLogin} className="bg-blue-500 text-white p-2 rounded">
        Login with OIDC
      </button>
    </div>
  );
}

function generateRandomString(length: number) {
  let text = '';
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  for (let i = 0; i < length; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }

  return text;
}

async function generateCodeChallenge(codeVerifier: string) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await window.crypto.subtle.digest('SHA-256', data);

  return btoa(String.fromCharCode.apply(null, [...new Uint8Array(digest)]))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
