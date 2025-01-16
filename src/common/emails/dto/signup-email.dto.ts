import { IsEmail, IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class SignupEmailDto {
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  name: string;

  @IsNumber()
  @IsNotEmpty()
  otp: number;
}
