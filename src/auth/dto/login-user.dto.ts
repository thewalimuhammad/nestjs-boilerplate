import { IsEmail, IsNotEmpty } from 'class-validator';

export class UserLoginDto {
  @IsEmail({}, { message: 'Invalid Email' })
  email: string;

  @IsNotEmpty({ message: 'Password cannot be empty' })
  password: string;
}
