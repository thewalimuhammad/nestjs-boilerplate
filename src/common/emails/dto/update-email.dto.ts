import { IsEmail, IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class UpdateEmailDto {
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  name: string;

  @IsEmail()
  newEmail: string;
}
