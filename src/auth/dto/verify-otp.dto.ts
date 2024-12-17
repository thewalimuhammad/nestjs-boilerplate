import { IsEmail, IsNotEmpty, Matches } from 'class-validator';

export class verifyOTPDto {
  @IsEmail({}, { message: 'Invalid Email' })
  email: string;

  @Matches(/^\d{4}$/, { message: 'OTP must be a 4-digit number' })
  otp: number;
}
