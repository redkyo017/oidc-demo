import Link from 'next/link';

export default function Home() {
  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">OIDC Demo</h1>
      <div>
        <Link href="/register" className="bg-blue-500 text-white p-2 rounded mr-2">
          Register
        </Link>
        <br/>
        <Link href="/login" className="bg-green-500 text-white p-2 rounded">
          Login
        </Link>
      </div>
    </div>
  );
}