import { IsEmail, IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class ForgetPasswordDto {
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  name: string;

  @IsNumber()
  @IsNotEmpty()
  otp: number;
}
