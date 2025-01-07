import { PrismaAdapter } from '@auth/prisma-adapter';
import bcrypt from 'bcrypt';
import { getServerSession, NextAuthOptions } from 'next-auth';
import { Adapter } from 'next-auth/adapters';
import AppleProvider from 'next-auth/providers/apple';
import CredentialsProvider from 'next-auth/providers/credentials';
import GithubProvider from 'next-auth/providers/github';
import GoogleProvider from 'next-auth/providers/google';
import { db } from './db';

export const authOptions: NextAuthOptions = {
    session: {
        strategy: 'jwt',
    },
    pages: {
        error: '/sign-in',
        signIn: '/sign-in',
    },
    adapter: PrismaAdapter(db) as Adapter,
    providers: [
        GoogleProvider({
            clientId: process.env.GOOGLE_CLIENT_ID!,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        }),
        GithubProvider({
            clientId: process.env.GITHUB_CLIENT_ID!,
            clientSecret: process.env.GITHUB_CLIENT_SECRET!,
        }),
        AppleProvider({
            clientId: process.env.APPLE_CLIENT_ID!,
            clientSecret: process.env.APPLE_CLIENT_SECRET!,
        }),
        CredentialsProvider({
            name: 'credentials',
            credentials: {
                name: { label: 'Name', type: 'text', placeholder: 'Name' },
                email: { label: 'Email', type: 'text', placeholder: 'Email' },
                password: { label: 'Password', type: 'text', placeholder: 'Password' },
            },
            async authorize(credentials, req) {
                if (!credentials?.email || !credentials?.password) {
                    throw new Error('Please enter email and password');
                }

                const user = await db.user.findUnique({
                    where: {
                        email: credentials.email,
                    },
                });

                if (!user || !user?.hashedPassword) {
                    throw new Error('User not found. Please try again.');
                }

                const passwordMatch = await bcrypt.compare(
                    credentials.password,
                    user.hashedPassword
                );

                if (!passwordMatch) {
                    throw new Error(
                        'The entered password is not correct. Please try again.'
                    );
                }

                return user;
            },
        }),
    ],
    secret: process.env.NEXTAUTH_SECRET,
    callbacks: {
        async session({ session, token }) {
            if (token) {
                session.user.id = token.id;
                session.user?.name = token.name;
                session.user?.email = token.email;
                session.user?.image = token.picture;
                session.user?.username = token.username;
            }

            const user = await db.user.findUnique({
                where: {
                    id: token.id,
                },
            });

            if (user) {
                session.user?.image = user.image;
                session.user?.name = user.name.toLowerCase();
            }

            return session;
        },
        async jwt({ token, user }) {
            const dbUser = await db.user.findUnique({
                where: {
                    email: token.email!,
                },
            });

            if (!dbUser) {
                token.id = user!.id;
                return token;
            }

            return {
                id: dbUser.id,
                name: dbUser.name,
                email: dbUser.email,
                picture: dbUser.image,
            };
        },
    },
};

export const getAuthSession = () => getServerSession(authOptions);
