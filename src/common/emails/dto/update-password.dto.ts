import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class UpdatePasswordDto {
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  name: string;
}
