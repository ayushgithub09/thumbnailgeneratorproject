import { PrismaAdapter } from "@auth/prisma-adapter";
import { type DefaultSession, type NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";

import { db } from "~/server/db";
import bcrypt from "bcryptjs";
import { signInSchema } from "~/schema/auth";
import { ZodError } from "zod";
import { env } from "process";

/**
 * Module augmentation for `next-auth` types. Allows us to add custom properties to the `session`
 * object and keep type safety.
 *
 * @see https://next-auth.js.org/getting-started/typescript#module-augmentation
 */
declare module "next-auth" {
  interface Session extends DefaultSession {
    user: {
      id: string;
      // ...other properties
      // role: UserRole;
    } & DefaultSession["user"];
  }

  // interface User {
  //   // ...other properties
  //   // role: UserRole;
  // }
}

declare module "next-auth/jwt" {
  interface JWT{
    id: string;
  }
}

/**
 * Options for NextAuth.js used to configure adapters, providers, callbacks, etc.
 *
 * @see https://next-auth.js.org/configuration/options
 */
export const authConfig = {
  providers: [
    Credentials({
      credentials: {
        email: {},
        password: {}
      },
      async authorize(credentials){
        try {
          const {email, password} =   // if there is not a valid email or password then parseAsync will throw an error that is written inside catch block
            await signInSchema.parseAsync(credentials);

          const user = await db.user.findUnique({
            where: {
              email: email,
            },
          });

          if(!user){
            throw new Error ("User not found");
          }

          const validPassword = await bcrypt.compare(password, user.password);

          if(!validPassword){
            return null;
          }

          return user

        }catch (error){
          if(error instanceof ZodError){
            return null;
          }
        }
        return  null;
      },
    }),
    /**
     * ...add more providers here.
     *
     * Most other providers require a bit more work than the Discord provider. For example, the
     * GitHub provider requires you to add the `refresh_token_expires_in` field to the Account
     * model. Refer to the NextAuth.js docs for the provider you want to use. Example:
     *
     * @see https://next-auth.js.org/providers/github
     */
  ],
  pages: {
    signIn: "/signIn",
  },
  secret: env.NEXTAUTH_SECRET,
  session:{
    strategy: "jwt",
  },

  adapter: PrismaAdapter(db),
  callbacks: {
    session: ({ session, user }) => ({
      ...session,
      user: {
        ...session.user,
        id: user.id,
      },
    }),
  },
} satisfies NextAuthConfig;
