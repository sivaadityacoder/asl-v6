import NextAuth, { type DefaultSession } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";

declare module "next-auth" {
  interface User {
    access_token?: string;
    refresh_token?: string;
    role?: string;
    plan_tier?: string;
  }
  interface Session {
    access_token?: string;
    refresh_token?: string;
    user: User & DefaultSession["user"];
  }
}

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
        otp: { label: "OTP Code", type: "text" },
      },
      async authorize(credentials) {
        if (!credentials?.email) return null;

        try {
          const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
          let res;
          
          if (credentials.otp) {
            res = await fetch(`${API_URL}/api/v1/auth/otp/verify`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                email: credentials.email,
                token: credentials.otp,
              }),
            });
          } else if (credentials.password) {
            res = await fetch(`${API_URL}/api/v1/auth/login`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                email: credentials.email,
                password: credentials.password,
              }),
            });
          } else {
            return null;
          }

          const data = await res.json();

          if (res.ok && data.user) {
            return {
              id: data.user.id,
              email: data.user.email,
              name: data.user.full_name,
              image: data.user.avatar_url,
              access_token: data.access_token,
              refresh_token: data.refresh_token,
              role: data.user.role,
              plan_tier: data.user.plan_tier,
            };
          }
          return null;
        } catch (e) {
          console.error("Auth error:", e);
          return null;
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id;
        token.access_token = user.access_token;
        token.refresh_token = user.refresh_token;
        token.role = user.role;
        token.plan_tier = user.plan_tier;
      }
      return token;
    },
    async session({ session, token }) {
      if (token && session.user) {
        session.user.id = token.id as string;
        session.user.role = token.role as string;
        session.user.plan_tier = token.plan_tier as string;
        session.access_token = token.access_token as string;
        session.refresh_token = token.refresh_token as string;
      }
      return session;
    },
  },
  pages: {
    signIn: "/login",
  },
  session: {
    strategy: "jwt",
    // Token expires in 30 days (session cookie); the backend JWT (30 min)
    // is refreshed client-side using the refresh_token callback.
    maxAge: 30 * 24 * 60 * 60,
  },
  secret: process.env.AUTH_SECRET || process.env.NEXTAUTH_SECRET || process.env.SECRET_KEY,
});
