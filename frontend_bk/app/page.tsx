
import Link from 'next/link';

export default function Home() {
  return (
    <div>
      <Link href="/register" className="bg-blue-500 text-white p-2 rounded mr-2">
        Register
      </Link>
      <Link href="/login" className="bg-green-500 text-white p-2 rounded">
        Login
      </Link>
    </div>
  );
}
