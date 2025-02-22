import { object, string } from 'zod';

export const signInSchema = object({
    email: string({required_error: 'Email is required'})
        .min(1,"Email is required")
        .email({message: 'Invalid email'}),
    password: string({required_error: "Password is required"})
        .min(1,"Password is required")
        .min(8,"Password must be atleast 8 characters")
        .max(32,"Password must be atmost 32 characters")
});